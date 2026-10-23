// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! Escenario de caso de uso: agente de soporte con LLM sobre datos JSON en claro.
//!
//! Ver `docs/use-cases/agent-support.md`. Este modulo solo existe en `cargo test`.
//!
//! Los tests usan los almacenes globales del kernel, asi que cada test usa
//! identificadores de tenant y subject propios para no interferir con los demas.
//! Nunca se mantiene un candado global mientras se llama a las funciones
//! `*_via_capability`, que lo toman por dentro.

use crate::audit::{self, AuditOp, AuditOutcome};
use crate::capabilities::*;
use alloc::vec::Vec;

const PEDIDOS_JSONL: &str = include_str!("../../docs/use-cases/fixtures/pedidos.jsonl");

/// Sustituto del futuro servicio `importer` de espacio de usuario: guarda cada
/// linea JSON tal cual (bytes originales, sin convertir) como un objeto por cliente.
/// Devuelve (customer_id, object_id, linea).
fn import_jsonl(tenant: u64, importer: u64, jsonl: &str) -> Vec<(u64, ObjectId, &str)> {
    let mut out = Vec::new();
    for line in jsonl.lines().filter(|l| !l.trim().is_empty()) {
        let key = "\"customer_id\":";
        let start = line.find(key).expect("customer_id") + key.len();
        let digits: alloc::string::String =
            line[start..].chars().take_while(|c| c.is_ascii_digit()).collect();
        let customer_id: u64 = digits.parse().expect("numeric id");
        let id = create_global_object(
            tenant,
            importer,
            ResourceType::Data,
            customer_id,
            Rights::READ,
            line.as_bytes().to_vec(),
        );
        assert_ne!(id, ObjectId(0), "el importador debe poder crear el objeto");
        out.push((customer_id, id, line));
    }
    out
}

/// Capability raiz del operador sobre un objeto, con derecho a delegar.
fn operator_cap(operator: u64, tenant: u64, object: ObjectId) -> CapabilityHandle {
    grant_object_capability(
        operator,
        tenant,
        ResourceType::Data,
        object.0,
        Rights::READ | Rights::DELEGATE,
    )
    .expect("el operador recibe la capability")
}

fn delegate(
    operator: u64,
    from: CapabilityHandle,
    agent: u64,
    rights: Rights,
) -> Result<CapabilityHandle, CapabilityError> {
    GLOBAL_CAPABILITY_BOOK
        .lock()
        .delegate(operator, from, agent, rights)
}

#[test]
fn agent_reads_only_its_customer_and_injection_is_just_data() {
    const ACME: u64 = 9100;
    const OPERATOR: u64 = 9101;
    const IMPORTER: u64 = 9102;
    const AGENT: u64 = 9103;

    // 1. Importacion: JSON en claro, un objeto por cliente.
    let imported = import_jsonl(ACME, IMPORTER, PEDIDOS_JSONL);
    assert_eq!(imported.len(), 3);
    let (_, obj_123, line_123) = imported[0];
    let (_, obj_124, _) = imported[1];

    // 2. El operador delega al agente SOLO lectura del cliente 123.
    let op_123 = operator_cap(OPERATOR, ACME, obj_123);
    let agent_123 = delegate(OPERATOR, op_123, AGENT, Rights::READ).expect("delegacion");

    // 3. Lectura legitima: los bytes JSON salen intactos, incluida la inyeccion.
    let bytes = read_object_via_capability(AGENT, agent_123, Rights::READ).expect("lectura");
    assert_eq!(bytes, line_123.as_bytes());
    assert!(core::str::from_utf8(&bytes).unwrap().contains("IGNORA TUS INSTRUCCIONES"));

    // 4. Ataque: el agente obedece la inyeccion y prueba lo que no deberia.
    //    a) Handle inventado hacia otro cliente.
    let forged = CapabilityHandle { slot: 7, generation: 1 };
    assert_eq!(
        read_object_via_capability(AGENT, forged, Rights::READ),
        Err(CapabilityError::NotFound)
    );
    //    b) Su propio slot con generacion adivinada.
    let wrong_gen = CapabilityHandle { slot: agent_123.slot, generation: agent_123.generation + 5 };
    assert_eq!(
        read_object_via_capability(AGENT, wrong_gen, Rights::READ),
        Err(CapabilityError::InvalidGeneration)
    );
    //    c) Escalar a escritura con la capability de lectura.
    assert_eq!(
        write_object_via_capability(AGENT, agent_123, Rights::WRITE, b"{}".to_vec()),
        Err(CapabilityError::PermissionDenied)
    );
    //    d) Re-delegar: su capability no lleva DELEGATE.
    assert_eq!(
        delegate(AGENT, agent_123, 9999, Rights::READ),
        Err(CapabilityError::InvalidDelegation)
    );
    //    e) Pedir al operador una delegacion ampliada es imposible desde el agente;
    //       y el operador no puede delegar mas de lo que tiene.
    let op_124 = operator_cap(OPERATOR, ACME, obj_124);
    assert_eq!(
        delegate(OPERATOR, op_124, AGENT, Rights::READ | Rights::WRITE),
        Err(CapabilityError::InvalidDelegation)
    );

    // 5. Tras los ataques, el acceso legitimo sigue funcionando.
    assert!(read_object_via_capability(AGENT, agent_123, Rights::READ).is_ok());

    // 6. Fin de sesion: revocar corta el acceso del agente.
    GLOBAL_CAPABILITY_BOOK
        .lock()
        .revoke(OPERATOR, op_123)
        .expect("revocacion");
    assert!(read_object_via_capability(AGENT, agent_123, Rights::READ).is_err());

    // 7. Auditoria: todo lo anterior quedo registrado, en orden, sin contenido.
    let trail: alloc::vec::Vec<(AuditOp, AuditOutcome)> = audit::events_for_subject(AGENT)
        .iter()
        .map(|e| (e.op, e.outcome))
        .collect();
    use AuditOutcome::{Allowed, Denied};
    assert_eq!(
        trail,
        alloc::vec![
            (AuditOp::Read, Allowed),
            (AuditOp::Read, Denied(CapabilityError::NotFound)),
            (AuditOp::Read, Denied(CapabilityError::InvalidGeneration)),
            (AuditOp::Write, Denied(CapabilityError::PermissionDenied)),
            (AuditOp::Delegate, Denied(CapabilityError::InvalidDelegation)),
            (AuditOp::Read, Allowed),
            // Tras la revocacion el handle del agente ya no se resuelve.
            (AuditOp::Read, Denied(CapabilityError::InvalidGeneration)),
        ]
    );

    // El evento de escritura denegada identifica tenant y objeto (el handle era valido).
    let denied_write = audit::events_for_subject(AGENT)
        .into_iter()
        .find(|e| e.op == AuditOp::Write)
        .expect("evento de escritura");
    assert_eq!(denied_write.handle, Some(agent_123));
    assert_eq!(denied_write.tenant_id, Some(ACME));
    assert_eq!(denied_write.resource_id, Some(obj_123.0));

    // Y el operador queda registrado: delegar, el intento ampliado denegado y la revocacion.
    let operator_ops: alloc::vec::Vec<(AuditOp, AuditOutcome)> =
        audit::events_for_subject(OPERATOR)
            .iter()
            .filter(|e| e.op != AuditOp::Grant)
            .map(|e| (e.op, e.outcome))
            .collect();
    assert_eq!(
        operator_ops,
        alloc::vec![
            (AuditOp::Delegate, Allowed),
            (AuditOp::Delegate, Denied(CapabilityError::InvalidDelegation)),
            (AuditOp::Revoke, Allowed),
        ]
    );
}

#[test]
fn other_tenant_subject_cannot_use_a_handle_it_does_not_hold() {
    const ACME: u64 = 9200;
    const OTHER: u64 = 9201;
    const OPERATOR: u64 = 9202;
    const IMPORTER: u64 = 9203;
    const AGENT: u64 = 9204;
    const FOREIGN: u64 = 9205;

    let imported = import_jsonl(ACME, IMPORTER, PEDIDOS_JSONL);
    let op = operator_cap(OPERATOR, ACME, imported[0].1);
    let agent = delegate(OPERATOR, op, AGENT, Rights::READ).unwrap();

    // Un sujeto de otro tenant presenta el handle del agente: su tabla no lo contiene.
    let _ = OTHER;
    assert_eq!(
        read_object_via_capability(FOREIGN, agent, Rights::READ),
        Err(CapabilityError::NotFound)
    );
}

#[test]
fn agent_capability_quota_limits_how_many_customers_it_can_hold() {
    const ACME: u64 = 9300;
    const OPERATOR: u64 = 9301;
    const IMPORTER: u64 = 9302;
    const AGENT: u64 = 9303;

    let mut delegated = 0;
    let mut last = Ok(CapabilityHandle { slot: 0, generation: 0 });
    for n in 0..(MAX_CAPABILITIES_PER_SUBJECT as u64 + 1) {
        let obj = create_global_object(
            ACME,
            IMPORTER,
            ResourceType::Data,
            n,
            Rights::READ,
            b"{}".to_vec(),
        );
        // Un operador distinto por objeto: el limite que se prueba es el del AGENTE,
        // no el de la tabla del operador (que tambien tiene su cuota).
        let operator = OPERATOR + 1000 + n;
        let op = operator_cap(operator, ACME, obj);
        last = delegate(operator, op, AGENT, Rights::READ);
        if last.is_ok() {
            delegated += 1;
        }
    }
    assert_eq!(delegated, MAX_CAPABILITIES_PER_SUBJECT);
    assert_eq!(last, Err(CapabilityError::CapabilityQuotaExceeded));
}

#[test]
fn oversized_json_record_is_rejected_by_the_object_store() {
    const ACME: u64 = 9400;
    let big = alloc::vec![b'x'; MAX_OBJECT_PAYLOAD_BYTES + 1];
    let id = GLOBAL_OBJECT_STORE.lock().try_create(
        ACME,
        9401,
        ResourceType::Data,
        1,
        Rights::READ,
        big,
    );
    assert_eq!(id, Err(CapabilityError::PayloadTooLarge));
}

/// I-05 (cerrada): la comprobacion de tenant es simetrica.
///
/// Dos capas de defensa:
/// 1. `grant_object_capability` no crea una capability de datos cuyo tenant
///    difiera del del objeto.
/// 2. Aunque una capability asi se inserte por otra via (aqui, directamente en
///    el libro), `read_object_via_capability` la rechaza con `TenantMismatch`.
#[test]
fn read_rejects_capability_whose_tenant_differs_from_the_object() {
    const ACME: u64 = 9500;
    const OTHER: u64 = 9501;
    const IMPORTER: u64 = 9502;
    const INTRUDER: u64 = 9503;

    let imported = import_jsonl(ACME, IMPORTER, PEDIDOS_JSONL);
    let target = imported[0].1;

    // Capa 1: el grant mismo se rechaza.
    assert!(grant_object_capability(
        INTRUDER,
        OTHER,
        ResourceType::Data,
        target.0,
        Rights::READ
    )
    .is_none());
    let grant_event = audit::events_for_subject(INTRUDER)
        .into_iter()
        .find(|e| e.op == AuditOp::Grant)
        .expect("el grant denegado queda auditado");
    assert_eq!(
        grant_event.outcome,
        AuditOutcome::Denied(CapabilityError::TenantMismatch)
    );
    assert_eq!(grant_event.tenant_id, Some(OTHER));
    assert_eq!(grant_event.resource_id, Some(target.0));

    // Capa 2: una capability mal formada que llegue al libro se rechaza al leer.
    let forged = GLOBAL_CAPABILITY_BOOK
        .lock()
        .try_grant(INTRUDER, OTHER, ResourceType::Data, target.0, Rights::READ)
        .expect("insercion directa en el libro");
    assert_eq!(
        read_object_via_capability(INTRUDER, forged, Rights::READ),
        Err(CapabilityError::TenantMismatch)
    );
    let read_event = audit::events_for_subject(INTRUDER)
        .into_iter()
        .find(|e| e.op == AuditOp::Read)
        .expect("la lectura denegada queda auditada");
    assert_eq!(
        read_event.outcome,
        AuditOutcome::Denied(CapabilityError::TenantMismatch)
    );
}

#[test]
fn grant_rejects_data_capability_for_missing_object() {
    assert!(grant_object_capability(
        9601,
        9600,
        ResourceType::Data,
        u64::MAX - 1,
        Rights::READ
    )
    .is_none());
}

#[test]
fn session_limits_cap_how_many_reads_an_agent_gets() {
    const ACME: u64 = 9700;
    const OPERATOR: u64 = 9701;
    const IMPORTER: u64 = 9702;
    const AGENT: u64 = 9703;

    let imported = import_jsonl(ACME, IMPORTER, PEDIDOS_JSONL);
    let op = operator_cap(OPERATOR, ACME, imported[0].1);
    let agent = GLOBAL_CAPABILITY_BOOK
        .lock()
        .delegate_limited(
            OPERATOR,
            op,
            AGENT,
            Rights::READ,
            Limits { expires_at: None, max_uses: Some(3) },
        )
        .expect("delegacion con tope de lecturas");

    for _ in 0..3 {
        assert!(read_object_via_capability(AGENT, agent, Rights::READ).is_ok());
    }
    assert_eq!(
        read_object_via_capability(AGENT, agent, Rights::READ),
        Err(CapabilityError::UsesExhausted)
    );

    let trail: Vec<AuditOutcome> = audit::events_for_subject(AGENT)
        .iter()
        .map(|e| e.outcome)
        .collect();
    assert_eq!(
        trail,
        alloc::vec![
            AuditOutcome::Allowed,
            AuditOutcome::Allowed,
            AuditOutcome::Allowed,
            AuditOutcome::Denied(CapabilityError::UsesExhausted),
        ]
    );
}

#[test]
fn expired_session_capability_is_rejected_and_audited() {
    const ACME: u64 = 9800;
    const OPERATOR: u64 = 9801;
    const IMPORTER: u64 = 9802;
    const AGENT: u64 = 9803;

    let imported = import_jsonl(ACME, IMPORTER, PEDIDOS_JSONL);
    let op = operator_cap(OPERATOR, ACME, imported[0].1);
    // `expires_at = 0` ya esta vencida con cualquier reloj: prueba determinista.
    let agent = GLOBAL_CAPABILITY_BOOK
        .lock()
        .delegate_limited(
            OPERATOR,
            op,
            AGENT,
            Rights::READ,
            Limits { expires_at: Some(0), max_uses: None },
        )
        .expect("delegacion");

    assert_eq!(
        read_object_via_capability(AGENT, agent, Rights::READ),
        Err(CapabilityError::Expired)
    );
    let last = audit::events_for_subject(AGENT).pop().expect("evento");
    assert_eq!(last.outcome, AuditOutcome::Denied(CapabilityError::Expired));
    assert_eq!(last.tenant_id, Some(ACME));
}
