// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! Cambio de contexto real (parche 14, I-29).
//!
//! `sched.rs` decide QUE tarea corre; este modulo hace que la CPU cambie de verdad.
//!
//! Diseño:
//! - Cada tarea tiene su propia pila de kernel (pool estatico). `TSS.rsp0` (interrupciones desde
//!   Ring 3) y `SYSCALL_STACK_TOP` (syscalls) apuntan siempre a la pila de la tarea que corre.
//! - El cambio apila los registros callee-saved y intercambia `rsp` (`switch_context`). Los
//!   registros de usuario no se pierden: el stub del timer y la entrada de syscall ya los
//!   guardan en la pila de la tarea; el resto lo guarda `switch_context`.
//! - Una tarea nueva arranca con una pila fabricada (`initial_frame`): al "volver" de
//!   `switch_context` cae en `task_first_entry`, que pone a cero los registros y hace `iretq`
//!   a Ring 3. Asi no se filtran valores del kernel a la tarea.
//! - El tick usa `try_lock` sobre el planificador y nunca se queda esperando. Las
//!   interrupciones solo estan abiertas en Ring 3 y en `irq_window()`, donde el codigo
//!   interrumpido no tiene ningun candado tomado.
//! - Cada tarea recuerda su CR3 y su `ProcessContext` (identidad). Al cambiar se restauran
//!   ambos, de modo que `current_process()` y la validacion de memoria de usuario siempre
//!   hablan de la tarea que corre.
//!
//! Limitaciones: un solo nucleo; el target no usa SSE/x87 (soft-float), por eso no se guarda
//! estado FPU; no hay `exit` ni liberacion de pilas todavia.
//!
//! Interruptor de biseccion: `SCHEDULER_ENABLED = false` deja el arranque como en el parche 13
//! (una sola tarea, `jump_to_ring3`).

#![allow(dead_code)]

use crate::process::ProcessContext;

/// `false`: sin planificador (una sola tarea, `Yield` no hace nada).
pub const SCHEDULER_ENABLED: bool = true;
/// `false`: no se crea la tarea de prueba (solo la shell).
pub const SPINNER_ENABLED: bool = true;

pub const KSTACK_SIZE: usize = 16 * 1024;
/// Tareas simultaneas con pila de kernel propia (shell, spinner y hasta seis procesos lanzados).
pub const MAX_KTASKS: usize = 8;

/// Selectores de Ring 3 segun la GDT: 0x18 datos, 0x20 codigo, con RPL = 3.
pub const USER_SS: u64 = 0x18 | 3;
pub const USER_CS: u64 = 0x20 | 3;

/// Palabras de la pila fabricada: 6 callee-saved + direccion de retorno + marco de `iretq` (5).
pub const INITIAL_FRAME_WORDS: usize = 12;

/// Pila inicial de una tarea nueva, de menor a mayor direccion, tal como la consume
/// `switch_context` (6 `pop`, un `ret`) y despues `iretq`:
/// `r15 r14 r13 r12 rbx rbp | ret=trampolin | rip cs rflags rsp ss`.
pub const fn initial_frame(
    trampoline: u64,
    user_rip: u64,
    user_rsp: u64,
    user_rflags: u64,
) -> [u64; INITIAL_FRAME_WORDS] {
    [0, 0, 0, 0, 0, 0, trampoline, user_rip, USER_CS, user_rflags, user_rsp, USER_SS]
}

/// Estado de una tarea que el planificador no guarda.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KTask {
    pub pid: u64,
    /// `rsp` de kernel guardado al suspenderla (o el inicial si aun no ha corrido).
    pub rsp: u64,
    /// Cima de su pila de kernel.
    pub stack_top: u64,
    pub cr3: u64,
    pub process: ProcessContext,
    /// Indice de su pila de kernel en el pool (para devolverla al terminar).
    pub stack_idx: usize,
}

/// Pool de indices de pila de kernel: se reutilizan al recoger un proceso terminado.
pub struct SlotPool {
    used: [bool; MAX_KTASKS],
}

impl SlotPool {
    pub const fn new() -> Self {
        Self { used: [false; MAX_KTASKS] }
    }

    pub fn alloc(&mut self) -> Option<usize> {
        let i = self.used.iter().position(|u| !*u)?;
        self.used[i] = true;
        Some(i)
    }

    /// Devuelve un indice. `false` si no estaba en uso (doble liberacion) o esta fuera de rango.
    pub fn free(&mut self, idx: usize) -> bool {
        match self.used.get_mut(idx) {
            Some(u) if *u => {
                *u = false;
                true
            }
            _ => false,
        }
    }

    pub fn in_use(&self) -> usize {
        self.used.iter().filter(|u| **u).count()
    }
}

pub static STACK_POOL: spin::Mutex<SlotPool> = spin::Mutex::new(SlotPool::new());

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KTableError {
    ZeroPid,
    Duplicate,
    Full,
}

/// Tabla fija de tareas con pila propia (codigo puro: se prueba en el host).
pub struct KTable {
    slots: [Option<KTask>; MAX_KTASKS],
}

impl KTable {
    pub const fn new() -> Self {
        Self { slots: [None; MAX_KTASKS] }
    }

    pub fn add(&mut self, task: KTask) -> Result<usize, KTableError> {
        if task.pid == 0 {
            return Err(KTableError::ZeroPid);
        }
        if self.slot_of(task.pid).is_some() {
            return Err(KTableError::Duplicate);
        }
        let slot = self.slots.iter().position(|s| s.is_none()).ok_or(KTableError::Full)?;
        self.slots[slot] = Some(task);
        Ok(slot)
    }

    pub fn slot_of(&self, pid: u64) -> Option<usize> {
        self.slots.iter().position(|s| s.map_or(false, |t| t.pid == pid))
    }

    pub fn get(&self, pid: u64) -> Option<&KTask> {
        self.slot_of(pid).and_then(|i| self.slots[i].as_ref())
    }

    pub fn get_mut(&mut self, pid: u64) -> Option<&mut KTask> {
        let i = self.slot_of(pid)?;
        self.slots[i].as_mut()
    }

    /// Quita una tarea de la tabla (al recogerla) y la devuelve.
    pub fn remove(&mut self, pid: u64) -> Option<KTask> {
        let i = self.slot_of(pid)?;
        self.slots[i].take()
    }

    pub fn len(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }
}

pub static KTASKS: spin::Mutex<KTable> = spin::Mutex::new(KTable::new());

/// Aplica una decision del planificador. En el host no hay CPU que cambiar.
fn apply(decision: crate::sched::Decision) {
    #[cfg(not(test))]
    if let crate::sched::Decision::Switch { from, to } = decision {
        hw::switch_to(from, to);
    }
    #[cfg(test)]
    let _ = decision;
}

/// Tick del temporizador: cuenta el quantum y conmuta si toca. Nunca espera un candado.
pub fn on_timer_tick() {
    if !SCHEDULER_ENABLED {
        return;
    }
    let decision = match crate::sched::SCHEDULER.try_lock() {
        Some(mut s) => {
            // Respaldo del despertar de la IRQ4: si quedo entrada sin entregar, se despierta aqui.
            if crate::console::has_input() {
                if let Some(pid) = crate::console::take_waiter() {
                    let _ = s.unblock(pid);
                }
            }
            s.on_tick(crate::clock::now())
        }
        None => return,
    };
    apply(decision);
}

/// Desde la IRQ4: despierta a la tarea dormida esperando entrada. Con `try_lock`; si el
/// planificador esta ocupado, el siguiente tick lo repite.
pub fn wake_console_waiter() {
    if !SCHEDULER_ENABLED || !crate::console::has_waiter() {
        return;
    }
    if let Some(mut s) = crate::sched::SCHEDULER.try_lock() {
        if let Some(pid) = crate::console::take_waiter() {
            let _ = s.unblock(pid);
        }
    }
}

/// Espera a que haya entrada de consola. Con otra tarea lista se bloquea (la IRQ4 la despierta);
/// si no hay nadie mas, duerme la CPU con `sti; hlt` (sin sondeo). Devuelve cuando conviene
/// volver a mirar el buffer; el llamante repite el ciclo. Se llama con interrupciones cerradas.
pub fn wait_for_input() {
    #[cfg(not(test))]
    hw::wait_for_input();
}

/// La tarea actual cede la CPU (syscall `Yield`, espera de teclado). Devuelve cuando vuelve a
/// correr. Sin planificador, o con una sola tarea, vuelve de inmediato.
pub fn yield_current() {
    if !SCHEDULER_ENABLED {
        return;
    }
    let decision = crate::sched::SCHEDULER.lock().yield_now();
    if let Ok(d) = decision {
        apply(d);
    }
}

#[cfg(not(test))]
pub use hw::{create_task, kstack_slot, start};

/// Plataforma real para `ProcessSpawn/Exit/Wait` (ver `syscall/spawn.rs`).
#[cfg(not(test))]
pub struct HwPlatform;

#[cfg(not(test))]
impl crate::syscall::spawn::Platform for HwPlatform {
    fn create_process(&self, ctx: ProcessContext, args: &[u8]) -> Result<(), trunomy_abi::Errno> {
        hw::create_process(ctx, args).map_err(|_| trunomy_abi::Errno::ResourceUnavailable)
    }
    fn exit_current(&self, pid: u64, wake_parent: Option<u64>) {
        crate::net::close_pid(pid);
        hw::exit_current(pid, wake_parent)
    }
    fn reap(&self, pid: u64) {
        crate::net::close_pid(pid);
        hw::reap(pid)
    }
    fn block_for_child(&self, child: u64, deadline: Option<u64>) {
        hw::block_for_child(child, deadline)
    }
    fn now(&self) -> u64 {
        crate::clock::now()
    }
    fn terminate(&self, pid: u64, wake_parent: Option<u64>) {
        crate::net::close_pid(pid);
        hw::terminate(pid, wake_parent)
    }
    fn admit_memory(&self) -> Result<(), trunomy_abi::Errno> {
        hw::admit_memory()
    }
    fn cpu_quota_exceeded(&self, pid: u64) -> bool {
        crate::sched::SCHEDULER.lock().over_quota(pid)
    }
}

#[cfg(not(test))]
mod hw {
    use super::*;
    use crate::guard::GuardedStack;
    use crate::process::CURRENT_PROCESS;
    use crate::sched::{Decision, SavedContext, SCHEDULER};

    // Cada pila de kernel lleva una pagina de guarda debajo (I-36).
    static mut KSTACKS: [GuardedStack<KSTACK_SIZE>; MAX_KTASKS] = [const { GuardedStack::new() }; MAX_KTASKS];

    pub fn kstack_slot(idx: usize) -> crate::guard::Slot {
        crate::guard::slot((&raw const KSTACKS) as u64, idx, KSTACK_SIZE)
    }
    /// Traza por el serie al crear/recoger procesos (para verificar en QEMU que se liberan).
    const SPAWN_TRACE: bool = true;
    /// Destino del `rsp` guardado cuando la tarea saliente ya no existe en la tabla.
    static mut DISCARD_RSP: u64 = 0;

    #[unsafe(naked)]
    unsafe extern "C" fn switch_context(save_rsp: *mut u64, next_rsp: u64) {
        core::arch::naked_asm!(
            "push rbp", "push rbx", "push r12", "push r13", "push r14", "push r15",
            "mov [rdi], rsp",
            "mov rsp, rsi",
            "pop r15", "pop r14", "pop r13", "pop r12", "pop rbx", "pop rbp",
            "ret",
        )
    }

    #[unsafe(naked)]
    unsafe extern "C" fn first_switch(next_rsp: u64) -> ! {
        core::arch::naked_asm!(
            "mov rsp, rdi",
            "pop r15", "pop r14", "pop r13", "pop r12", "pop rbx", "pop rbp",
            "ret",
        )
    }

    /// Primera instruccion de una tarea nueva: borra los registros que el kernel dejo sucios
    /// y entra a Ring 3 con el marco que preparo `initial_frame`.
    #[unsafe(naked)]
    unsafe extern "C" fn task_first_entry() -> ! {
        core::arch::naked_asm!(
            "xor eax, eax", "xor ecx, ecx", "xor edx, edx", "xor esi, esi", "xor edi, edi",
            "xor r8d, r8d", "xor r9d, r9d", "xor r10d, r10d", "xor r11d, r11d",
            "iretq",
        )
    }

    fn set_kernel_stack(top: u64) {
        crate::gdt::set_rsp0(top);
        crate::syscalls::set_syscall_stack_top(top);
    }

    fn current_cr3() -> u64 {
        let cr3: u64;
        unsafe { core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags)) };
        cr3 & !0xFFF
    }

    fn load_address_space(cr3: u64) {
        if current_cr3() != cr3 {
            crate::memory::set_active_user_pml4(cr3);
            unsafe { core::arch::asm!("mov cr3, {}", in(reg) cr3, options(nostack, preserves_flags)) };
        } else {
            crate::memory::set_active_user_pml4(cr3);
        }
    }

    /// Crea una tarea de Ring 3 lista para correr: reserva su pila de kernel, fabrica el marco
    /// inicial y la da de alta en la tabla y en el planificador. Solo antes de `start` o con
    /// interrupciones cerradas.
    pub unsafe fn create_task(
        pid: u64,
        cr3: u64,
        user_rip: u64,
        user_rsp: u64,
        process: ProcessContext,
    ) -> Result<(), &'static str> {
        create_task_limited(pid, cr3, user_rip, user_rsp, process, None)
    }

    /// Como `create_task`, con una cuota de CPU en ticks (I-40; `None` = sin cuota).
    pub unsafe fn create_task_limited(
        pid: u64,
        cr3: u64,
        user_rip: u64,
        user_rsp: u64,
        process: ProcessContext,
        cpu_limit: Option<u64>,
    ) -> Result<(), &'static str> {
        let idx = STACK_POOL.lock().alloc().ok_or("no free kernel stacks")?;
        // El espacio de direcciones debe haber heredado las guardas: si no, se rechaza (falla cerrado).
        if crate::guard::verify_space(cr3).is_err() {
            STACK_POOL.lock().free(idx);
            return Err("a guard page is mapped in the address space");
        }
        // Y la politica W^X del kernel (I-37): un espacio que no la herede no se crea.
        if crate::kmap::verify_space(cr3).is_err() {
            STACK_POOL.lock().free(idx);
            return Err("the kernel map does not satisfy W^X in the address space");
        }
        let top = kstack_slot(idx).top;
        let frame = initial_frame(
            task_first_entry as *const () as u64,
            user_rip,
            user_rsp,
            crate::interrupts::user_rflags(crate::interrupts::TIMER_ENABLED),
        );
        let rsp = top - (INITIAL_FRAME_WORDS * 8) as u64;
        core::ptr::copy_nonoverlapping(frame.as_ptr(), rsp as *mut u64, INITIAL_FRAME_WORDS);

        if KTASKS.lock().add(KTask { pid, rsp, stack_top: top, cr3, process, stack_idx: idx }).is_err() {
            STACK_POOL.lock().free(idx);
            return Err("task table full or duplicate pid");
        }
        if SCHEDULER.lock().spawn_limited(pid, SavedContext { kernel_rsp: rsp, cr3 }, cpu_limit).is_err() {
            KTASKS.lock().remove(pid);
            STACK_POOL.lock().free(idx);
            return Err("the scheduler rejected the task");
        }
        Ok(())
    }

    /// Crea un proceso nuevo con la imagen de la shell verificada al arrancar: espacio de
    /// direcciones propio (a partir de la PML4 base), codigo, pila, VGA y la pagina de argumentos.
    pub fn create_process(ctx: ProcessContext, args: &[u8]) -> Result<(), &'static str> {
        if !SCHEDULER_ENABLED {
            return Err("no scheduler");
        }
        let (payload, entry) = crate::image::registered().ok_or("no verified image")?;
        let base = crate::memory::base_pml4().ok_or("no base PML4")?;
        // create_user_space_from no toca el espacio activo, asi que el llamante sigue validando
        // sus punteros contra su propio espacio.
        let mut pml4 = unsafe { crate::memory::ProcessPml4::create_user_space_from(base) }.ok_or("out of memory")?;
        let built = unsafe { crate::image::populate(&mut pml4, payload, entry, args) };
        let rip = match built {
            Ok(rip) => rip,
            Err(e) => {
                unsafe { pml4.destroy() };
                return Err(e);
            }
        };
        if let Err(e) = unsafe {
            create_task_limited(ctx.pid, pml4.cr3_phys, rip, crate::image::USER_STACK_TOP, ctx, Some(crate::quota::WORKER_CPU_TICKS))
        } {
            unsafe { pml4.destroy() };
            return Err(e);
        }
        if SPAWN_TRACE {
            crate::print_uart("[KERNEL] process ");
            crate::print_uart_hex(ctx.pid);
            crate::print_uart(" created (");
            crate::print_uart_hex(args.len() as u64);
            crate::print_uart(" bytes of arguments)\n");
        }
        Ok(())
    }

    /// Cuota de memoria (I-40): el proceso nuevo cabe en `MAX_PROCESS_FRAMES` y tras crearlo
    /// quedan al menos `KERNEL_RESERVE_FRAMES` marcos libres. No reserva nada.
    pub fn admit_memory() -> Result<(), trunomy_abi::Errno> {
        let (payload, _) = crate::image::registered().ok_or(trunomy_abi::Errno::ResourceUnavailable)?;
        let needed = crate::quota::frames_needed(payload.len());
        let free = crate::memory::BITMAP_ALLOCATOR.lock().free_frames();
        crate::quota::admit(needed, free).map_err(|_| trunomy_abi::Errno::QuotaExceeded)
    }

    /// El proceso actual termina. Despierta al padre si dormia y cede la CPU para siempre.
    pub fn exit_current(pid: u64, wake_parent: Option<u64>) {
        let decision = {
            let mut s = SCHEDULER.lock();
            if let Some(parent) = wake_parent {
                let _ = s.unblock(parent);
            }
            s.exit(pid)
        };
        // Esta pila ya no se reanuda: se puede abandonar (`from = None`). El padre la libera
        // con `reap` cuando recoja el codigo de salida.
        if let Ok(Decision::Switch { to, .. }) = decision {
            switch_to(None, to);
        }
        // Nadie listo: dormir hasta que una IRQ (teclado, timer) deje algo listo.
        loop {
            unsafe { core::arch::asm!("sti", "hlt", "cli", options(nomem, nostack)) };
            if let Decision::Switch { to, .. } = SCHEDULER.lock().start() {
                switch_to(None, to);
            }
        }
    }

    /// Libera lo de un hijo ya terminado: su pila de kernel y su espacio de direcciones.
    pub fn reap(pid: u64) {
        let Some(task) = KTASKS.lock().remove(pid) else { return };
        STACK_POOL.lock().free(task.stack_idx);
        let freed = unsafe { (crate::memory::ProcessPml4 { cr3_phys: task.cr3 }).destroy() };
        if SPAWN_TRACE {
            crate::print_uart("[KERNEL] process ");
            crate::print_uart_hex(pid);
            crate::print_uart(" reaped: ");
            crate::print_uart_hex(freed as u64);
            crate::print_uart(" frames freed, free now: ");
            crate::print_uart_hex(crate::memory::BITMAP_ALLOCATOR.lock().free_frames() as u64);
            crate::print_uart("\n");
        }
    }

    /// Retira a OTRO proceso del planificador (nunca al actual): no vuelve a correr, y deja de
    /// ser el durmiente de la consola si lo era. Su pila y su espacio de direcciones se liberan
    /// con `reap` cuando el padre lo recoja. Despierta al padre si dormia esperandolo.
    pub fn terminate(pid: u64, wake_parent: Option<u64>) {
        {
            let mut s = SCHEDULER.lock();
            if let Some(parent) = wake_parent {
                let _ = s.unblock(parent);
            }
            // `exit` quita a `pid` de la cola de listos y de la tabla, este bloqueado o no.
            let _ = s.exit(pid);
        }
        crate::console::cancel_waiter(pid);
        if SPAWN_TRACE {
            crate::print_uart("[KERNEL] process ");
            crate::print_uart_hex(pid);
            crate::print_uart(" terminated by the kernel\n");
        }
    }

    /// El padre duerme hasta que `child` termine o llegue `deadline`. Si no puede dormir (nadie mas
    /// esta listo) la CPU espera una IRQ; en ambos casos el llamante vuelve a preguntar por el
    /// estado del hijo y por el plazo.
    pub fn block_for_child(child: u64, deadline: Option<u64>) {
        let mut s = SCHEDULER.lock();
        // Si el hijo ya agoto su cuota de CPU no se duerme: el llamante debe terminarlo ya.
        if s.over_quota(child) {
            return;
        }
        let me = match s.current() {
            Some(pid) if s.ready_count() > 0 => pid,
            _ => {
                drop(s);
                unsafe { core::arch::asm!("sti", "hlt", "cli", options(nomem, nostack)) };
                return;
            }
        };
        // Se deja constancia bajo el mismo candado: si el hijo agota la cuota mientras el padre
        // duerme, el planificador lo despierta (no espera a su plazo).
        if !s.watch(child, me) {
            return;
        }
        match s.block_current(deadline) {
            Ok(Decision::Switch { from, to }) => {
                drop(s);
                switch_to(from, to);
            }
            _ => {
                // No debia ocurrir (habia alguien listo): deshace y sigue corriendo.
                crate::proctab::PROCS.lock().cancel_wait(child);
                let _ = s.unblock(me);
                let _ = s.start();
            }
        }
    }

    /// Cede la CPU a la primera tarea y no vuelve. Interrupciones cerradas hasta el `iretq`.
    pub unsafe fn start() -> ! {
        let decision = SCHEDULER.lock().start();
        let to = match decision {
            Decision::Switch { to, .. } => to,
            _ => panic!("no tasks to start"),
        };
        let task = *KTASKS.lock().get(to).expect("the chosen task exists");
        set_kernel_stack(task.stack_top);
        *CURRENT_PROCESS.lock() = task.process;
        load_address_space(task.cr3);
        first_switch(task.rsp)
    }

    pub fn wait_for_input() {
        let mut s = SCHEDULER.lock();
        let me = match s.current() {
            Some(pid) if SCHEDULER_ENABLED && s.ready_count() > 0 => pid,
            _ => {
                // Nadie mas puede correr (o no hay planificador): la CPU duerme hasta una IRQ.
                drop(s);
                unsafe { core::arch::asm!("sti", "hlt", "cli", options(nomem, nostack)) };
                return;
            }
        };
        // Un solo durmiente: otra tarea que lea a la vez se queda con el `hlt` de arriba.
        if !crate::console::register_waiter(me) {
            drop(s);
            unsafe { core::arch::asm!("sti", "hlt", "cli", options(nomem, nostack)) };
            return;
        }
        // IF=0 desde la comprobacion del buffer hasta aqui: ninguna IRQ4 se cuela entre medias.
        match s.block_current(None) {
            Ok(Decision::Switch { from, to }) => {
                drop(s);
                switch_to(from, to);
            }
            _ => {
                // No debia ocurrir (habia alguien listo): deshace y sigue corriendo esta tarea.
                crate::console::cancel_waiter(me);
                let _ = s.unblock(me);
                let _ = s.start();
            }
        }
    }

    /// Cambia de la tarea `from` a `to`. Solo con interrupciones cerradas (manejador del timer
    /// o syscall) y sin candados tomados: la tarea que se suspende los retendria.
    pub fn switch_to(from: Option<u64>, to: u64) {
        let (save, next) = {
            let mut table = KTASKS.lock();
            let next = match table.get(to) {
                Some(t) => *t,
                None => return,
            };
            let save: *mut u64 = match from.and_then(|pid| table.get_mut(pid)) {
                Some(out) => {
                    out.process = *CURRENT_PROCESS.lock();
                    &mut out.rsp
                }
                None => &raw mut DISCARD_RSP,
            };
            (save, next)
        };
        set_kernel_stack(next.stack_top);
        *CURRENT_PROCESS.lock() = next.process;
        load_address_space(next.cr3);
        unsafe { switch_context(save, next.rsp) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task(pid: u64) -> KTask {
        KTask { pid, rsp: 0x1000 * pid, stack_top: 0x2000 * pid, cr3: 0x3000 * pid, process: ProcessContext::new(pid, pid, 1), stack_idx: 0 }
    }

    #[test]
    fn initial_frame_matches_what_switch_and_iretq_consume() {
        let f = initial_frame(0xAAAA, 0x4000_0000, 0x8000_0000, 0x202);
        assert_eq!(f.len(), INITIAL_FRAME_WORDS);
        // 6 registros callee-saved a cero: la tarea no hereda nada del kernel.
        assert!(f[..6].iter().all(|w| *w == 0));
        assert_eq!(f[6], 0xAAAA, "ret de switch_context -> trampolin");
        // marco de iretq: rip, cs, rflags, rsp, ss
        assert_eq!(&f[7..], &[0x4000_0000, USER_CS, 0x202, 0x8000_0000, USER_SS]);
    }

    #[test]
    fn user_selectors_are_ring3_and_match_the_gdt() {
        assert_eq!(USER_CS & 3, 3);
        assert_eq!(USER_SS & 3, 3);
        assert_eq!(USER_CS >> 3, 4, "GDT[4] = codigo de usuario");
        assert_eq!(USER_SS >> 3, 3, "GDT[3] = datos de usuario");
        // coherente con STAR[63:48] = 0x13 usado por sysret
        assert_eq!(USER_SS, 0x13 + 8);
        assert_eq!(USER_CS, 0x13 + 16);
    }

    #[test]
    fn initial_rflags_never_grant_io_or_trace() {
        let f = initial_frame(0, 0, 0, crate::interrupts::user_rflags(true));
        let rflags = f[9];
        assert_eq!(rflags & 0x200, 0x200, "IF=1 para que el timer pueda expropiar");
        assert_eq!(rflags & (0x3000 | 0x4000 | 0x100 | 0x400), 0);
    }

    #[test]
    fn ktable_adds_finds_and_rejects_bad_entries() {
        let mut t = KTable::new();
        assert_eq!(t.add(task(0)), Err(KTableError::ZeroPid));
        assert_eq!(t.add(task(1)), Ok(0));
        assert_eq!(t.add(task(2)), Ok(1));
        assert_eq!(t.add(task(1)), Err(KTableError::Duplicate));
        assert_eq!(t.slot_of(2), Some(1));
        assert_eq!(t.get(2).unwrap().cr3, 0x6000);
        assert!(t.get(9).is_none());
        t.get_mut(1).unwrap().rsp = 77;
        assert_eq!(t.get(1).unwrap().rsp, 77);
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn ktable_is_bounded() {
        let mut t = KTable::new();
        for pid in 1..=MAX_KTASKS as u64 {
            assert!(t.add(task(pid)).is_ok());
        }
        assert_eq!(t.add(task(99)), Err(KTableError::Full));
        assert_eq!(t.len(), MAX_KTASKS);
    }

    #[test]
    fn ktable_remove_frees_the_slot_for_reuse() {
        let mut t = KTable::new();
        for pid in 1..=MAX_KTASKS as u64 {
            t.add(task(pid)).unwrap();
        }
        assert_eq!(t.remove(3).map(|k| k.pid), Some(3));
        assert_eq!(t.remove(3), None);
        assert!(t.get(3).is_none());
        assert!(t.add(task(50)).is_ok(), "el hueco se reutiliza");
        assert_eq!(t.add(task(51)), Err(KTableError::Full));
    }

    #[test]
    fn stack_pool_reuses_freed_slots_and_rejects_double_free() {
        let mut p = SlotPool::new();
        let all: alloc::vec::Vec<usize> = (0..MAX_KTASKS).map(|_| p.alloc().unwrap()).collect();
        assert_eq!(all, (0..MAX_KTASKS).collect::<alloc::vec::Vec<_>>(), "indices unicos");
        assert_eq!(p.alloc(), None, "acotado");
        assert!(p.free(2));
        assert!(!p.free(2), "doble liberacion rechazada");
        assert!(!p.free(MAX_KTASKS), "fuera de rango");
        assert_eq!(p.alloc(), Some(2));
        assert_eq!(p.in_use(), MAX_KTASKS);
    }

    #[test]
    fn kernel_stack_is_large_and_aligned_for_the_abi() {
        assert!(KSTACK_SIZE >= 16 * 1024);
        assert_eq!(KSTACK_SIZE % 16, 0);
        assert!(INITIAL_FRAME_WORDS * 8 < KSTACK_SIZE);
    }

    #[test]
    fn yield_with_no_running_task_is_harmless() {
        // El planificador global esta vacio en el host: no debe fallar ni bloquearse.
        yield_current();
        on_timer_tick();
    }
}
