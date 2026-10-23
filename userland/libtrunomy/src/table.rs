// SPDX-License-Identifier: AGPL-3.0-only
// Trunomy OS - capability-based microkernel for isolating AI agents
// Copyright (C) 2026 Roberto C. Aleman F.
// https://github.com/robertoaleman/trunomy

//! Tablas de texto con bordes ASCII (`+`, `-`, `|`), sin dependencias y comprobables en el host.
//!
//! El ancho de cada columna es el de su celda mas larga. Una celda es texto de una linea: lo que no
//! sea ASCII imprimible (o sea `|`) se sustituye por `?`, de modo que ni un nombre ni un texto que venga de otro
//! proceso pueda mover el cursor ni dibujar bordes falsos (`|`) en la consola del operador (I-35).

use alloc::vec::Vec;

enum Row<const N: usize> {
    Rule,
    Cells([Vec<u8>; N]),
}

/// Una tabla de `N` columnas: cabecera, filas y lineas separadoras.
pub struct Table<const N: usize> {
    header: [&'static str; N],
    rows: Vec<Row<N>>,
}

fn clean(cell: &[u8]) -> Vec<u8> {
    cell.iter().map(|&b| if (0x20..0x7f).contains(&b) && b != b'|' { b } else { b'?' }).collect()
}

impl<const N: usize> Table<N> {
    pub fn new(header: [&'static str; N]) -> Self {
        Self { header, rows: Vec::new() }
    }

    /// Una linea separadora entre dos grupos de filas (la de arriba y la de abajo van solas).
    pub fn rule(&mut self) {
        if !matches!(self.rows.last(), None | Some(Row::Rule)) {
            self.rows.push(Row::Rule);
        }
    }

    /// Una fila; cada celda, una sola linea.
    pub fn row(&mut self, cells: [&[u8]; N]) {
        self.rows.push(Row::Cells(cells.map(clean)));
    }

    fn widths(&self) -> [usize; N] {
        let mut w = self.header.map(str::len);
        for r in &self.rows {
            if let Row::Cells(c) = r {
                for (i, cell) in c.iter().enumerate() {
                    w[i] = w[i].max(cell.len());
                }
            }
        }
        w
    }

    /// Escribe la tabla linea a linea por `out` (en el shell, `print_bytes`).
    pub fn render(&self, out: &mut dyn FnMut(&[u8])) {
        let w = self.widths();
        let rule = |out: &mut dyn FnMut(&[u8])| {
            for width in w {
                out(b"+");
                for _ in 0..width + 2 {
                    out(b"-");
                }
            }
            out(b"+\n");
        };
        let line = |out: &mut dyn FnMut(&[u8]), cells: &[&[u8]; N]| {
            for (i, cell) in cells.iter().enumerate() {
                out(b"| ");
                out(cell);
                for _ in cell.len()..w[i] + 1 {
                    out(b" ");
                }
            }
            out(b"|\n");
        };
        rule(out);
        line(out, &self.header.map(str::as_bytes));
        rule(out);
        for r in &self.rows {
            match r {
                Row::Rule => rule(out),
                Row::Cells(c) => line(out, &core::array::from_fn(|i| c[i].as_slice())),
            }
        }
        if !matches!(self.rows.last(), Some(Row::Rule)) {
            rule(out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;

    fn text<const N: usize>(t: &Table<N>) -> String {
        let mut s = Vec::new();
        t.render(&mut |b| s.extend_from_slice(b));
        String::from_utf8(s).unwrap()
    }

    #[test]
    fn columns_are_as_wide_as_their_longest_cell() {
        let mut t = Table::new(["A", "Bee"]);
        t.row([b"long-cell", b"x"]);
        t.row([b"y", b"1234567"]);
        let expect = "\
+-----------+---------+
| A         | Bee     |
+-----------+---------+
| long-cell | x       |
| y         | 1234567 |
+-----------+---------+
";
        assert_eq!(text(&t), expect);
    }

    #[test]
    fn a_rule_separates_groups_and_is_never_doubled_or_trailing() {
        let mut t = Table::new(["K", "V"]);
        t.rule(); // al principio no se dibuja: la cabecera ya lleva su linea
        t.row([b"a", b"1"]);
        t.rule();
        t.rule();
        t.row([b"b", b"2"]);
        t.rule();
        let expect = "\
+---+---+
| K | V |
+---+---+
| a | 1 |
+---+---+
| b | 2 |
+---+---+
";
        assert_eq!(text(&t), expect);
    }

    #[test]
    fn an_empty_table_is_just_the_header() {
        let t = Table::new(["Solo", "Cabecera"]);
        assert_eq!(text(&t), "+------+----------+\n| Solo | Cabecera |\n+------+----------+\n+------+----------+\n");
    }

    #[test]
    fn every_line_has_the_same_length() {
        let mut t = Table::new(["Tenant ID", "Entity (Role / User)", "PID", "Permissions / Capabilities"]);
        t.row([b"1000 netlab", b"nora", b"1000", b"object.create"]);
        t.row([b"", b"", b"", b"net.send"]);
        t.rule();
        t.row([b"1000 netlab", b"omar", b"1001", b"data#12:read,write uses=3"]);
        let s = text(&t);
        let lens: Vec<usize> = s.lines().map(str::len).collect();
        assert!(lens.iter().all(|l| *l == lens[0]), "{s}");
    }

    #[test]
    fn untrusted_bytes_cannot_break_the_table_or_move_the_cursor() {
        let mut t = Table::new(["X"]);
        t.row([b"a\nb\x1b[2J\r|\xff"]);
        let s = text(&t);
        // Una sola fila de datos: sin saltos de linea ni escapes dentro de la celda.
        assert_eq!(s.lines().count(), 5, "{s}");
        assert!(s.bytes().all(|b| b == b'\n' || (0x20..0x7f).contains(&b)));
        assert!(s.contains("| a?b?[2J??? |"), "{s}");
        assert_eq!(s.matches('|').count(), 4, "{s}");
    }
}
