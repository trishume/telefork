use std::error::Error;
use std::io::{Read, Write};
use std::ffi::c_void;

use libc;
use nix;
use nix::errno::Errno;
use nix::sys::ptrace;
use nix::sys::signal::{kill, raise, Signal};
use nix::sys::uio;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, ForkResult, Pid};

use proc_maps;

use bincode;
use serde::{Deserialize, Serialize};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const PAGE_SIZE: usize = 4096;

#[derive(Serialize, Deserialize)]
struct Mapping {
    name: Option<String>,
    readable: bool,
    writeable: bool,
    executable: bool,
    offset: usize,
    size: usize,
}

#[derive(Serialize, Deserialize)]
enum Command {
    Mapping(Mapping),
    Registers { len: usize },
}

fn is_special_kernel_map(map: &proc_maps::MapRange) -> bool {
    match map.filename() {
        Some(n) if (n == "[vdso]" || n == "[vsyscall]" || n == "[vvar]") => true,
        _ => false,
    }
}

fn should_skip_map(map: &proc_maps::MapRange) -> bool {
    // TODO handle non-library read-only things by remapping as readable
    // TODO or maybe preserve them without contents and map zero pages on rehydrate
    if !map.is_read() || map.size() == 0 {
        return true;
    }
    is_special_kernel_map(map)
}

fn error<T>(s: &'static str) -> Result<T> {
    Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, s)))
}

fn write_map(out: &mut dyn Write, child: Pid, map: &proc_maps::MapRange) -> Result<()> {
    if should_skip_map(map) {
        // eprintln!("Skipping {:?}", map);
        return Ok(());
    }
    let mapping = Mapping {
        name: map.filename().clone(),
        readable: map.is_read(),
        writeable: map.is_write(),
        executable: map.is_exec(),
        offset: map.start(),
        size: map.size(),
    };
    bincode::serialize_into::<&mut dyn Write, Command>(out, &Command::Mapping(mapping))?;

    // === write contents
    let mut remaining_size = map.size();
    let mut buf = vec![0u8; PAGE_SIZE];
    while remaining_size > 0 {
        let read_size = std::cmp::min(buf.len(), remaining_size);
        let offset = map.start() + (map.size() - remaining_size);
        // println!("trying read with ptrace");
        // let v = ptrace::read(child, offset as *mut core::ffi::c_void)?;
        // println!("{:?}", v);
        // println!("Reading from {:?}", map);
        let wrote = uio::process_vm_readv(
            child,
            &[uio::IoVec::from_mut_slice(&mut buf[..read_size])],
            &[uio::RemoteIoVec {
                base: offset,
                len: read_size,
            }],
        )?;
        if wrote == 0 {
            return error("failed to read from other process");
        }
        // println!("Read from other process");
        out.write(&buf[..])?;
        remaining_size -= read_size;
    }

    Ok(())
}

#[repr(C)]
struct RegInfo {
    regs: libc::user_regs_struct,
}

impl RegInfo {
    fn to_bytes(&self) -> &[u8] {
        let pointer = self as *const Self as *const u8;
        unsafe {
            std::slice::from_raw_parts(pointer, std::mem::size_of::<Self>())
        }
    }

    // fn from_bytes(bytes: &[u8]) -> Option<&Self> {
    //     if bytes.len() < std::mem::size_of::<Self>() {
    //         return None;
    //     }
    //     if bytes.as_ptr().align_offset(std::mem::align_of::<Self>()) != 0 {
    //         return None;
    //     }
    //     Some(unsafe { std::mem::transmute::<*const u8, &Self>(bytes.as_ptr()) })
    // }
}

fn write_state(out: &mut dyn Write, child: Pid) -> Result<()> {
    let maps = proc_maps::get_process_maps(child.as_raw() as proc_maps::Pid)?;
    // print_maps_info(&maps);

    for map in &maps {
        write_map(out, child, map)?;
    }

    // === Write registers
    let regs = RegInfo { regs: ptrace::getregs(child)? };
    let reg_bytes = regs.to_bytes();
    bincode::serialize_into::<&mut dyn Write, Command>(out, &Command::Registers { len: reg_bytes.len() })?;
    out.write(reg_bytes)?;

    Ok(())
}

enum NormalForkLocation {
    Parent(Pid),
    Woke,
}

fn kill_me_if_parent_dies() -> nix::Result<()> {
    let res = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) };
    Errno::result(res).map(|_| ())
}

fn fork_frozen_traced() -> Result<NormalForkLocation> {
    match fork()? {
        ForkResult::Parent { child, .. } => match waitpid(child, None)? {
            WaitStatus::Stopped(_, Signal::SIGSTOP) => Ok(NormalForkLocation::Parent(child)),
            _ => error("couldn't trace child"),
        },
        ForkResult::Child => {
            kill_me_if_parent_dies()?;
            ptrace::traceme()?;
            raise(Signal::SIGSTOP)?;
            Ok(NormalForkLocation::Woke)
        }
    }
}

#[derive(Debug)]
pub enum TeleforkLocation {
    Parent,
    Child,
}

fn _print_maps_info(maps: &[proc_maps::MapRange]) {
    for map in maps {
        println!("{:>7} {:>16x} {} {:?}", map.size(), map.start(), map.flags, map.filename());
        // println!("{:?}", map);
    }
    let total_size: usize = maps.iter().map(|m| m.size()).sum();
    println!("{:>7} total", total_size);
}

pub fn telefork(out: &mut dyn Write) -> Result<TeleforkLocation> {
    println!("teleforking");
    let child: Pid = match fork_frozen_traced()? {
        NormalForkLocation::Woke => return Ok(TeleforkLocation::Child),
        NormalForkLocation::Parent(p) => p,
    };
    write_state(out, child)?;

    kill(child, Signal::SIGKILL)?;
    Ok(TeleforkLocation::Parent)
}

fn single_step(child: Pid) -> Result<()> {
    ptrace::step(child, None)?;
    match waitpid(child, None)? {
        WaitStatus::Stopped(_, Signal::SIGTRAP) => Ok(()),
        _ => error("couldn't single step child"),
    }
}

pub fn telepad(inp: &mut dyn Read) -> Result<Pid> {
    println!("incoming on telepad");
    let child: Pid = match fork_frozen_traced()? {
        NormalForkLocation::Woke => panic!("should wake up as a different process!"),
        NormalForkLocation::Parent(p) => p,
    };

    let orig_maps = proc_maps::get_process_maps(child.as_raw() as proc_maps::Pid)?;
    // _print_maps_info(&orig_maps[..]);

    // FIXME find an address that is safe from both processes

    // ==== poke syscall into current rip
    let regs = ptrace::getregs(child)?;
    let old_word: i64 = ptrace::read(child, regs.rip as *mut c_void)?;
    // println!("old word = {:x}", old_word);
    // SYSCALL; JMP %rax
    let syscall_word: i64 = i64::from_ne_bytes([0x0f,0x05,0xff,0xe0,0,0,0,0]);
    // println!("new word = {:x}", syscall_word);
    ptrace::write(child, regs.rip as *mut c_void, syscall_word as *mut c_void)?;

    // ==== remote mmap syscall to map a page there
    let mmap_regs = libc::user_regs_struct {
        rax: 9, // mmap
        rdi: 0, // addr
        rsi: PAGE_SIZE as u64, // length
        rdx: (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as u64, // prot
        r10: (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64, // flags
        r8: (-1i64) as u64, // fd
        r9: 0, // offset
        ..regs
    };
    ptrace::setregs(child, mmap_regs)?;
    single_step(child)?;
    let regs = ptrace::getregs(child)?;
    let mmap_location: i64 = regs.rax as i64;
    println!("mmap location = {:x}; pre sys = {:x}; pre = {:x}", mmap_location, mmap_regs.rax as i64, regs.rax as i64);
    if mmap_location == -1 {
        error("failed to mmap")?;
    }

    // ==== jump to new region
    // single_step(child)?;
    // let regs = ptrace::getregs(child)?;
    // if regs.rip as i64 != mmap_location {
    //     error("jump unsuccessful")?;
    // }

    // ==== poke syscall into new page
    ptrace::write(child, mmap_location as *mut c_void, syscall_word as *mut c_void)?;

    // TODO remote munmap all original regions except vdso stuff
    for map in &orig_maps {
        if is_special_kernel_map(map) || map.size() == 0 {
            continue;
        }
        // println!("unmapping {:?}", map);
        let syscall_regs = libc::user_regs_struct {
            rip: mmap_location as u64, // syscall instr
            rax: 11, // munmap
            rdi: map.start() as u64, // addr
            rsi: map.size() as u64, // length
            ..regs
        };
        ptrace::setregs(child, syscall_regs)?;
        single_step(child)?;
        let new_regs = ptrace::getregs(child)?;
        if new_regs.rax != 0 {
            println!("rax = {:x}; rip = {:x}", new_regs.rax, new_regs.rip);
            error("failed to munmap")?;
        }
    }

    println!("========== new maps:");
    let maps = proc_maps::get_process_maps(child.as_raw() as proc_maps::Pid)?;
    _print_maps_info(&maps[..]);
    // TODO remote mremap vdso stuff

    // TODO remote mmap new areas
    // TODO writev new areas
    // TODO restore registers
    // TODO maybe jump to right place or maybe I can just restore rip
    // TODO resume

    Ok(child)
}
