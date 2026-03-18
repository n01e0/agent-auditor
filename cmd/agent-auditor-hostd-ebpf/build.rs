use std::{env, fs, path::PathBuf};

use object::write::{Object, Symbol, SymbolSection};
use object::{
    Architecture, BinaryFormat, Endianness, SectionKind, SymbolFlags, SymbolKind, SymbolScope,
};

const OBJECT_FILENAME: &str = "agent-auditor-hostd-poc.bpf.o";
const LICENSE: &[u8] = b"GPL\0";
const RETURN_ZERO_PROGRAM: [u8; 16] = [
    0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // r0 = 0
    0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
];

const PROGRAMS: [ProgramSpec; 2] = [
    ProgramSpec {
        name: "hostd_sched_process_exec",
        section: "tracepoint/sched/sched_process_exec",
    },
    ProgramSpec {
        name: "hostd_sched_process_exit",
        section: "tracepoint/sched/sched_process_exit",
    },
];

#[derive(Clone, Copy)]
struct ProgramSpec {
    name: &'static str,
    section: &'static str,
}

fn main() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR should be set"));
    let object_path = out_dir.join(OBJECT_FILENAME);

    fs::write(&object_path, build_object()).expect("embedded eBPF object should be generated");

    println!("cargo:rerun-if-changed=build.rs");
}

fn build_object() -> Vec<u8> {
    let mut object = Object::new(BinaryFormat::Elf, Architecture::Bpf, Endianness::Little);

    let license = object.add_section(Vec::new(), b"license".to_vec(), SectionKind::ReadOnlyData);
    object.append_section_data(license, LICENSE, 1);

    for program in PROGRAMS {
        add_program(&mut object, program);
    }

    object
        .write()
        .expect("embedded eBPF object should serialize")
}

fn add_program(object: &mut Object<'_>, program: ProgramSpec) {
    let section = object.add_section(
        Vec::new(),
        program.section.as_bytes().to_vec(),
        SectionKind::Text,
    );
    let offset = object.append_section_data(section, &RETURN_ZERO_PROGRAM, 8);

    object.add_symbol(Symbol {
        name: program.name.as_bytes().to_vec(),
        value: offset,
        size: RETURN_ZERO_PROGRAM.len() as u64,
        kind: SymbolKind::Text,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(section),
        flags: SymbolFlags::None,
    });
}
