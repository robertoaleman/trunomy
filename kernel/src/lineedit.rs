// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! Editor de linea de la consola serie, con historico (I-50).
//!
//! `ConsoleRead` entrega una linea ya armada. Antes, cualquier byte del teclado se guardaba y se
//! devolvia como eco, asi que una flecha (`ESC [ D`) llegaba al terminal como una orden de mover el
//! cursor: se podia salir de la linea de entrada y pisar el prompt. Aqui el teclado es una maquina de
//! estados pura (sin hardware, probada en el host) con estas reglas:
//!
//! - Solo entra ASCII imprimible (0x20..=0x7e). El resto de bytes de control se ignora.
//! - Las secuencias `ESC [ ...` y `ESC O ...` (flechas, Inicio, Supr, ...) se consumen enteras: ni
//!   se guardan en la linea ni se les hace eco. Solo ↑ y ↓ hacen algo: recorren el historico.
//! - El unico eco que se emite son los caracteres tecleados, `\b \b` al borrar, `\n` al terminar,
//!   `^C\n` al cancelar y el redibujo de una linea recordada. El cursor nunca sale de la linea
//!   de entrada: se escribe siempre al final.
//! - `Ctrl-U` borra la linea; `Ctrl-C` la cancela (devuelve una linea vacia).
//!
//! El historico guarda las ultimas `HIST_ENTRIES` lineas (sin vacias ni repetidas seguidas), solo
//! en RAM. Una orden puede llevar un secreto (`object create clave ...`): cada ranura se borra con
//! escrituras volatiles antes de reutilizarse y el buffer de la linea se borra al entregarla.

/// Tamano maximo de una linea (el shell pide 256).
pub const MAX_LINE: usize = 512;
/// Ordenes recordadas.
pub const HIST_ENTRIES: usize = 16;
/// Una linea mas larga que esto no se guarda en el historico.
pub const HIST_LINE: usize = 256;

/// Borra con escrituras volatiles: el compilador no puede quitarlas por ser memoria "que ya no se lee".
fn wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` es una referencia valida y alineada a un byte.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Ultimas ordenes tecleadas, de la mas reciente a la mas antigua.
pub struct History {
    lines: [[u8; HIST_LINE]; HIST_ENTRIES],
    lens: [usize; HIST_ENTRIES],
    /// Ranura donde se escribira la proxima.
    next: usize,
    count: usize,
}

impl History {
    pub const fn new() -> Self {
        Self { lines: [[0; HIST_LINE]; HIST_ENTRIES], lens: [0; HIST_ENTRIES], next: 0, count: 0 }
    }

    pub fn len(&self) -> usize {
        self.count
    }

    /// La orden de hace `back` posiciones (0 = la mas reciente).
    pub fn get(&self, back: usize) -> Option<&[u8]> {
        if back >= self.count {
            return None;
        }
        let slot = (self.next + HIST_ENTRIES - 1 - back) % HIST_ENTRIES;
        Some(&self.lines[slot][..self.lens[slot]])
    }

    /// Guarda una linea terminada. No guarda vacias, demasiado largas ni iguales a la ultima.
    pub fn push(&mut self, line: &[u8]) {
        if line.is_empty() || line.len() > HIST_LINE || self.get(0) == Some(line) {
            return;
        }
        let slot = self.next;
        wipe(&mut self.lines[slot]);
        self.lines[slot][..line.len()].copy_from_slice(line);
        self.lens[slot] = line.len();
        self.next = (slot + 1) % HIST_ENTRIES;
        self.count = (self.count + 1).min(HIST_ENTRIES);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Normal,
    /// Tras `ESC`.
    Esc,
    /// Dentro de `ESC [ ...`: parametros hasta un byte final (0x40..=0x7e).
    Csi,
    /// Tras `ESC O` (flechas en modo aplicacion): un byte final.
    Ss3,
}

/// Lo que ocurrio tras un byte.
#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    /// La linea sigue en edicion.
    Pending,
    /// Enter: la linea esta en `line()`.
    Line,
    /// Ctrl-C: no hay linea.
    Cancelled,
}

/// La linea que se esta tecleando y el estado del teclado.
pub struct LineEditor {
    buf: [u8; MAX_LINE],
    len: usize,
    max: usize,
    mode: Mode,
    /// Posicion del historico que se esta mostrando (0 = la mas reciente); `None` = linea propia.
    browse: Option<usize>,
}

impl LineEditor {
    /// `max` es lo que cabe en el buffer del que pide la linea (se recorta a `MAX_LINE`).
    pub const fn new(max: usize) -> Self {
        Self { buf: [0; MAX_LINE], len: 0, max: if max > MAX_LINE { MAX_LINE } else { max }, mode: Mode::Normal, browse: None }
    }

    pub fn line(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Borra la linea de la memoria (volatil). Se llama al entregarla.
    pub fn wipe(&mut self) {
        wipe(&mut self.buf);
        self.len = 0;
    }

    /// Un byte del teclado. `echo` recibe lo que hay que escribir en el terminal.
    pub fn feed(&mut self, byte: u8, hist: &mut History, echo: &mut dyn FnMut(u8)) -> Event {
        match self.mode {
            Mode::Esc => {
                self.mode = Mode::Normal;
                match byte {
                    b'[' => self.mode = Mode::Csi,
                    b'O' => self.mode = Mode::Ss3,
                    // `ESC` suelta (o Alt+tecla): se descarta el ESC y el byte sigue su camino normal.
                    _ => return self.normal(byte, hist, echo),
                }
                Event::Pending
            }
            Mode::Csi => {
                match byte {
                    0x20..=0x3f => {} // parametros e intermedios: se consumen
                    0x40..=0x7e => {
                        self.mode = Mode::Normal;
                        self.arrow(byte, hist, echo);
                    }
                    // Un control (Enter, Ctrl-C...) corta la secuencia y actua como siempre, para que
                    // un terminal que mande una secuencia incompleta no deje la consola atascada.
                    0x00..=0x1f => {
                        self.mode = Mode::Normal;
                        return self.normal(byte, hist, echo);
                    }
                    _ => self.mode = Mode::Normal,
                }
                Event::Pending
            }
            Mode::Ss3 => {
                self.mode = Mode::Normal;
                match byte {
                    0x40..=0x7e => self.arrow(byte, hist, echo),
                    0x00..=0x1f => return self.normal(byte, hist, echo),
                    _ => {}
                }
                Event::Pending
            }
            Mode::Normal => self.normal(byte, hist, echo),
        }
    }

    fn normal(&mut self, byte: u8, hist: &mut History, echo: &mut dyn FnMut(u8)) -> Event {
        match byte {
            0x1b => self.mode = Mode::Esc,
            b'\r' | b'\n' => {
                echo(b'\n');
                hist.push(&self.buf[..self.len]);
                self.browse = None;
                return Event::Line;
            }
            // Retroceso: solo borra lo tecleado; con la linea vacia no hace nada (no toca el prompt).
            0x08 | 0x7f => {
                if self.len > 0 {
                    self.len -= 1;
                    self.buf[self.len] = 0;
                    echo(0x08);
                    echo(b' ');
                    echo(0x08);
                }
                self.browse = None;
            }
            0x15 => {
                self.erase(echo);
                self.browse = None;
            }
            0x03 => {
                self.erase(echo);
                for b in *b"^C\n" {
                    echo(b);
                }
                self.browse = None;
                return Event::Cancelled;
            }
            0x20..=0x7e => {
                if self.len < self.max {
                    self.buf[self.len] = byte;
                    self.len += 1;
                    echo(byte);
                }
                self.browse = None;
            }
            // Tab, otros controles y bytes de 8 bits: se ignoran sin eco.
            _ => {}
        }
        Event::Pending
    }

    /// Una flecha o tecla de cursor: solo ↑ (`A`) y ↓ (`B`) hacen algo.
    fn arrow(&mut self, final_byte: u8, hist: &History, echo: &mut dyn FnMut(u8)) {
        let target = match (final_byte, self.browse) {
            (b'A', None) if hist.len() > 0 => Some(0),
            (b'A', Some(i)) if i + 1 < hist.len() => Some(i + 1),
            (b'B', Some(0)) => None,
            (b'B', Some(i)) => Some(i - 1),
            _ => return, // otra tecla, o ya en el extremo del historico
        };
        self.erase(echo);
        if let Some(i) = target {
            if let Some(entry) = hist.get(i) {
                let n = entry.len().min(self.max);
                self.buf[..n].copy_from_slice(&entry[..n]);
                self.len = n;
                for &b in &entry[..n] {
                    echo(b);
                }
            }
        }
        self.browse = target;
    }

    /// Borra la linea de la pantalla y de la memoria (solo hacia atras: `\b \b`).
    fn erase(&mut self, echo: &mut dyn FnMut(u8)) {
        for _ in 0..self.len {
            echo(0x08);
            echo(b' ');
            echo(0x08);
        }
        wipe(&mut self.buf[..self.len]);
        self.len = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    /// Teclea `keys` y devuelve los eventos y el eco.
    fn keys(ed: &mut LineEditor, h: &mut History, keys: &[u8]) -> (Vec<Event>, Vec<u8>) {
        let mut echo = Vec::new();
        let mut events = Vec::new();
        for &k in keys {
            events.push(ed.feed(k, h, &mut |b| echo.push(b)));
        }
        (events, echo)
    }

    fn run_line(h: &mut History, text: &str) {
        let mut ed = LineEditor::new(256);
        let mut input = text.as_bytes().to_vec();
        input.push(b'\r');
        let (ev, _) = keys(&mut ed, h, &input);
        assert_eq!(ev.last(), Some(&Event::Line));
    }

    const UP: &[u8] = b"\x1b[A";
    const DOWN: &[u8] = b"\x1b[B";

    #[test]
    fn a_typed_line_is_echoed_and_returned() {
        let (mut ed, mut h) = (LineEditor::new(256), History::new());
        let (ev, echo) = keys(&mut ed, &mut h, b"net up\r");
        assert_eq!(ev.last(), Some(&Event::Line));
        assert_eq!(ed.line(), b"net up");
        assert_eq!(echo, b"net up\n");
    }

    #[test]
    fn cursor_keys_are_swallowed_whole_and_never_echoed() {
        for seq in [&b"\x1b[D"[..], b"\x1b[C", b"\x1b[H", b"\x1b[F", b"\x1b[3~", b"\x1b[1;5D", b"\x1b[2J", b"\x1bOD", b"\x1bOH"] {
            let (mut ed, mut h) = (LineEditor::new(256), History::new());
            keys(&mut ed, &mut h, b"ab");
            let (ev, echo) = keys(&mut ed, &mut h, seq);
            assert!(ev.iter().all(|e| *e == Event::Pending), "{seq:?}");
            assert!(echo.is_empty(), "{seq:?} produjo eco {echo:?}: movera el cursor");
            assert_eq!(ed.line(), b"ab", "{seq:?} se colo en la linea");
            // y se sigue escribiendo al final, como si nada
            keys(&mut ed, &mut h, b"c");
            assert_eq!(ed.line(), b"abc");
        }
    }

    #[test]
    fn the_cursor_can_never_leave_the_input_line() {
        // Las unicas salidas posibles son caracteres imprimibles y `\b \b` en la cantidad tecleada,
        // `\n` y el `^C`: nunca ESC ni un `\b` suelto que retroceda mas de lo escrito.
        let (mut ed, mut h) = (LineEditor::new(256), History::new());
        let mut all = Vec::new();
        for chunk in [&b"\x1b[D\x1b[D"[..], b"ab", b"\x7f\x7f\x7f\x7f\x08", b"\x1b[D", b"x", b"\x15\x15", UP, DOWN, b"\t\x01\x02\x04\xff\x80"] {
            all.extend(keys(&mut ed, &mut h, chunk).1);
        }
        let mut depth: i32 = 0; // caracteres tecleados que se pueden borrar
        let mut i = 0;
        while i < all.len() {
            match all[i] {
                0x20..=0x7e => depth += 1,
                0x08 => {
                    assert_eq!(&all[i..i + 3], b"\x08 \x08", "retroceso suelto");
                    depth -= 1;
                    assert!(depth >= 0, "se borro mas de lo escrito (el prompt)");
                    i += 2;
                }
                b => panic!("byte de control {b:#x} en el eco"),
            }
            i += 1;
        }
    }

    #[test]
    fn backspace_on_an_empty_line_does_nothing() {
        let (mut ed, mut h) = (LineEditor::new(256), History::new());
        let (_, echo) = keys(&mut ed, &mut h, b"\x7f\x08\x7f");
        assert!(echo.is_empty());
        let (_, echo) = keys(&mut ed, &mut h, b"ab\x7f\x7f\x7f");
        assert_eq!(echo, b"ab\x08 \x08\x08 \x08");
        assert_eq!(ed.line(), b"");
    }

    #[test]
    fn only_printable_ascii_enters_the_line() {
        let (mut ed, mut h) = (LineEditor::new(256), History::new());
        let (_, echo) = keys(&mut ed, &mut h, b"a\x00\x01\x02\t\x07\x0b\x0c\x0e\x1f\x80\xc3\xbb\xffb");
        assert_eq!(ed.line(), b"ab");
        assert_eq!(echo, b"ab");
    }

    #[test]
    fn an_incomplete_sequence_does_not_swallow_enter() {
        let (mut ed, mut h) = (LineEditor::new(256), History::new());
        let (ev, _) = keys(&mut ed, &mut h, b"hi\x1b[1;\r");
        assert_eq!(ev.last(), Some(&Event::Line));
        assert_eq!(ed.line(), b"hi");
        // ESC suelta seguida de una letra: el ESC se descarta y la letra entra.
        let (mut ed, mut h) = (LineEditor::new(256), History::new());
        keys(&mut ed, &mut h, b"\x1bx");
        assert_eq!(ed.line(), b"x");
        // una secuencia que termina en un byte de 8 bits se abandona sin dejar el estado atascado
        let (mut ed, mut h) = (LineEditor::new(256), History::new());
        keys(&mut ed, &mut h, b"\x1b[\xffok");
        assert_eq!(ed.line(), b"ok");
    }

    #[test]
    fn the_line_never_exceeds_the_callers_buffer() {
        let (mut ed, mut h) = (LineEditor::new(4), History::new());
        let (_, echo) = keys(&mut ed, &mut h, b"abcdefgh");
        assert_eq!(ed.line(), b"abcd");
        assert_eq!(echo, b"abcd");
        let ed = LineEditor::new(10_000);
        assert_eq!(ed.max, MAX_LINE);
    }

    #[test]
    fn ctrl_u_clears_the_line_and_ctrl_c_cancels_it() {
        let (mut ed, mut h) = (LineEditor::new(256), History::new());
        let (_, echo) = keys(&mut ed, &mut h, b"abc\x15");
        assert_eq!(echo, b"abc\x08 \x08\x08 \x08\x08 \x08");
        assert_eq!(ed.line(), b"");
        let (ev, echo) = keys(&mut ed, &mut h, b"xy\x03");
        assert_eq!(ev.last(), Some(&Event::Cancelled));
        assert_eq!(echo, b"xy\x08 \x08\x08 \x08^C\n");
        assert_eq!(ed.line(), b"");
        assert_eq!(h.len(), 0, "una linea cancelada no entra en el historico");
    }

    #[test]
    fn history_recalls_newest_first_and_stops_at_the_ends() {
        let mut h = History::new();
        for l in ["uno", "dos", "tres"] {
            run_line(&mut h, l);
        }
        let mut ed = LineEditor::new(256);
        keys(&mut ed, &mut h, UP);
        assert_eq!(ed.line(), b"tres");
        keys(&mut ed, &mut h, UP);
        assert_eq!(ed.line(), b"dos");
        keys(&mut ed, &mut h, UP);
        keys(&mut ed, &mut h, UP);
        keys(&mut ed, &mut h, UP);
        assert_eq!(ed.line(), b"uno", "en la mas antigua se queda");
        keys(&mut ed, &mut h, DOWN);
        assert_eq!(ed.line(), b"dos");
        keys(&mut ed, &mut h, DOWN);
        keys(&mut ed, &mut h, DOWN);
        assert_eq!(ed.line(), b"", "pasada la mas reciente queda la linea vacia");
        keys(&mut ed, &mut h, DOWN);
        assert_eq!(ed.line(), b"");
    }

    #[test]
    fn a_recalled_line_replaces_what_was_typed_and_can_be_edited_and_run() {
        let mut h = History::new();
        run_line(&mut h, "net up");
        let mut ed = LineEditor::new(256);
        keys(&mut ed, &mut h, b"zzz");
        let (_, echo) = keys(&mut ed, &mut h, UP);
        assert_eq!(echo, b"\x08 \x08\x08 \x08\x08 \x08net up", "se borra lo tecleado y se dibuja la orden");
        keys(&mut ed, &mut h, b"\x7f\x7fdown");
        assert_eq!(ed.line(), b"net down");
        let (ev, _) = keys(&mut ed, &mut h, b"\r");
        assert_eq!(ev, [Event::Line]);
        assert_eq!(h.get(0), Some(&b"net down"[..]));
        assert_eq!(h.get(1), Some(&b"net up"[..]));
    }

    #[test]
    fn history_with_nothing_stored_does_nothing() {
        let (mut ed, mut h) = (LineEditor::new(256), History::new());
        let (_, echo) = keys(&mut ed, &mut h, b"ab");
        let (_, e2) = keys(&mut ed, &mut h, UP);
        assert!(e2.is_empty() && echo == b"ab");
        assert_eq!(ed.line(), b"ab");
        keys(&mut ed, &mut h, DOWN);
        assert_eq!(ed.line(), b"ab");
    }

    #[test]
    fn empty_repeated_and_long_lines_are_not_remembered() {
        let mut h = History::new();
        run_line(&mut h, "");
        run_line(&mut h, "a");
        run_line(&mut h, "a");
        run_line(&mut h, "b");
        run_line(&mut h, "a");
        assert_eq!(h.len(), 3);
        h.push(&[b'x'; HIST_LINE + 1]);
        assert_eq!(h.len(), 3);
        h.push(&[b'y'; HIST_LINE]);
        assert_eq!(h.len(), 4);
    }

    #[test]
    fn only_the_last_sixteen_are_kept() {
        let mut h = History::new();
        for i in 0..40 {
            run_line(&mut h, &std::format!("cmd{i}"));
        }
        assert_eq!(h.len(), HIST_ENTRIES);
        assert_eq!(h.get(0), Some(&b"cmd39"[..]));
        assert_eq!(h.get(HIST_ENTRIES - 1), Some(&b"cmd24"[..]));
        assert_eq!(h.get(HIST_ENTRIES), None);
    }

    #[test]
    fn a_reused_slot_leaves_no_trace_of_the_older_secret() {
        let mut h = History::new();
        h.push(b"object create clave hunter2-hunter2-hunter2");
        for i in 0..HIST_ENTRIES - 1 {
            h.push(&[b'a' + i as u8]);
        }
        // la proxima escritura reutiliza la ranura del secreto, con una linea mas corta
        h.push(b"ok");
        let slot = &h.lines[0];
        assert_eq!(&slot[..2], b"ok");
        assert!(slot[2..].iter().all(|b| *b == 0), "quedan restos de la orden anterior");
    }

    #[test]
    fn a_delivered_line_can_be_wiped_from_the_editor() {
        let (mut ed, mut h) = (LineEditor::new(256), History::new());
        keys(&mut ed, &mut h, b"secreto\r");
        assert_eq!(ed.line(), b"secreto");
        ed.wipe();
        assert!(ed.buf.iter().all(|b| *b == 0));
        assert_eq!(ed.line(), b"");
    }

    #[test]
    fn a_recalled_line_longer_than_the_buffer_is_cut_to_fit() {
        let mut h = History::new();
        run_line(&mut h, "abcdefgh");
        let mut ed = LineEditor::new(4);
        keys(&mut ed, &mut h, UP);
        assert_eq!(ed.line(), b"abcd");
    }

    #[test]
    fn every_stored_line_is_printable_ascii() {
        let mut h = History::new();
        let mut ed = LineEditor::new(256);
        let all: Vec<u8> = (0..=255u8).collect();
        for chunk in all.chunks(7) {
            keys(&mut ed, &mut h, chunk);
            keys(&mut ed, &mut h, b"\r");
        }
        for i in 0..h.len() {
            assert!(h.get(i).unwrap().iter().all(|b| (0x20..0x7f).contains(b)));
        }
    }
}
