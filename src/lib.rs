use std::error::Error;
use std::ffi::c_void;
use std::io::{Read, Write};

use libc;
use libc::{PROT_EXEC, PROT_READ, PROT_WRITE};

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

#[derive(Serialize, Deserialize, Debug)]
struct Mapping {
    name: Option<String>,
    readable: bool,
    writeable: bool,
    executable: bool,
    addr: usize,
    size: usize,
}

impl Mapping {
    fn _prot(&self) -> i32 {
        let mut prot = 0;
        if self.readable {
            prot |= PROT_READ;
        }
        if self.writeable {
            prot |= PROT_WRITE;
        }
        if self.executable {
            prot |= PROT_EXEC;
        }
        prot
    }
}

#[derive(Serialize, Deserialize)]
enum Command {
    Mapping(Mapping),
    ResumeWithRegisters { len: usize },
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
        addr: map.start(),
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
    pub regs: libc::user_regs_struct,
}

impl RegInfo {
    fn to_bytes(&self) -> &[u8] {
        let pointer = self as *const Self as *const u8;
        unsafe { std::slice::from_raw_parts(pointer, std::mem::size_of::<Self>()) }
    }

    fn from_bytes(bytes: &[u8]) -> Option<&Self> {
        if bytes.len() < std::mem::size_of::<Self>() {
            return None;
        }
        if bytes.as_ptr().align_offset(std::mem::align_of::<Self>()) != 0 {
            return None;
        }
        Some(unsafe { std::mem::transmute::<*const u8, &Self>(bytes.as_ptr()) })
    }
}

fn write_state(out: &mut dyn Write, child: Pid) -> Result<()> {
    let maps = proc_maps::get_process_maps(child.as_raw() as proc_maps::Pid)?;
    // print_maps_info(&maps);

    for map in &maps {
        write_map(out, child, map)?;
    }

    // === Write registers
    let regs = RegInfo {
        regs: ptrace::getregs(child)?,
    };
    let reg_bytes = regs.to_bytes();
    bincode::serialize_into::<&mut dyn Write, Command>(
        out,
        &Command::ResumeWithRegisters {
            len: reg_bytes.len(),
        },
    )?;
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
            println!("hello from forked child!");
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
        println!(
            "{:>7} {:>16x} {} {:?}",
            map.size(),
            map.start(),
            map.flags,
            map.filename()
        );
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

#[derive(Copy, Clone)]
struct SyscallLoc(u64);

fn remote_mmap_anon(
    child: Pid,
    syscall: SyscallLoc,
    addr: Option<usize>,
    length: usize,
    prot: i32,
) -> Result<usize> {
    if length % PAGE_SIZE != 0 {
        error("mmap length must be multiple of page size")?;
    }
    let SyscallLoc(loc) = syscall;
    let regs = ptrace::getregs(child)?;
    let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
    let (addr, flags) = match addr {
        Some(addr) => (addr, flags | libc::MAP_FIXED),
        None => (0, flags),
    };
    let mmap_regs = libc::user_regs_struct {
        rip: loc,
        rax: 9,             // mmap
        rdi: addr as u64,   // addr
        rsi: length as u64, // length
        rdx: prot as u64,   // prot
        r10: flags as u64,  // flags
        r8: (-1i64) as u64, // fd
        r9: 0,              // offset
        ..regs
    };
    ptrace::setregs(child, mmap_regs)?;
    single_step(child)?;
    let regs = ptrace::getregs(child)?;
    let mmap_location: i64 = regs.rax as i64;
    // println!("mmap location = {:x}; pre sys = {:x}; pre = {:x}", mmap_location, mmap_regs.rax as i64, regs.rax as i64);
    if mmap_location == -1 {
        error("mmap syscall exited with -1")?;
    }
    if addr != 0 && mmap_location as usize != addr {
        error("failed to mmap at correct location")?;
    }
    Ok(mmap_location as usize)
}

fn remote_munmap(child: Pid, syscall: SyscallLoc, addr: usize, length: usize) -> Result<()> {
    let SyscallLoc(loc) = syscall;
    let regs = ptrace::getregs(child)?;
    let syscall_regs = libc::user_regs_struct {
        rip: loc as u64,    // syscall instr
        rax: 11,            // munmap
        rdi: addr as u64,   // addr
        rsi: length as u64, // length
        ..regs
    };
    ptrace::setregs(child, syscall_regs)?;
    single_step(child)?;
    let new_regs = ptrace::getregs(child)?;
    if new_regs.rax != 0 {
        // println!("rax = {:x}; rip = {:x}", new_regs.rax, new_regs.rip);
        error("failed to munmap")?;
    }
    Ok(())
}

fn stream_memory(child: Pid, inp: &mut dyn Read, addr: usize, length: usize) -> Result<()> {
    let mut remaining_size = length;
    let mut buf = vec![0u8; PAGE_SIZE];
    while remaining_size > 0 {
        let batch_size = std::cmp::min(buf.len(), remaining_size);
        let offset = addr + (length - remaining_size);

        inp.read_exact(&mut buf[..batch_size])?;

        let wrote = uio::process_vm_writev(
            child,
            &[uio::IoVec::from_slice(&buf[..batch_size])],
            &[uio::RemoteIoVec {
                base: offset,
                len: batch_size,
            }],
        )?;
        if wrote == 0 {
            return error("failed to write to process");
        }
        remaining_size -= batch_size;
    }

    Ok(())
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
    // let old_word: i64 = ptrace::read(child, regs.rip as *mut c_void)?;
    // println!("old word = {:x}", old_word);
    // SYSCALL; JMP %rax
    let syscall_word: i64 = i64::from_ne_bytes([0x0f, 0x05, 0xff, 0xe0, 0, 0, 0, 0]);
    // println!("new word = {:x}", syscall_word);
    ptrace::write(child, regs.rip as *mut c_void, syscall_word as *mut c_void)?;
    let temp_syscall = SyscallLoc(regs.rip as u64);

    // ==== remote mmap syscall to map a page there
    let prot_all = PROT_READ | PROT_WRITE | PROT_EXEC;
    let mmap_location = remote_mmap_anon(
        child,
        temp_syscall,
        None,
        PAGE_SIZE,
        prot_all,
    )?;

    // ==== jump to new region
    // single_step(child)?;
    // let regs = ptrace::getregs(child)?;
    // if regs.rip as i64 != mmap_location {
    //     error("jump unsuccessful")?;
    // }

    // ==== poke syscall into new page
    ptrace::write(
        child,
        mmap_location as *mut c_void,
        syscall_word as *mut c_void,
    )?;
    let syscall = SyscallLoc(mmap_location as u64);

    // ==== remote munmap all original regions except vdso stuff
    for map in &orig_maps {
        if is_special_kernel_map(map) || map.size() == 0 {
            continue;
        }
        // println!("unmapping {:?}", map);
        remote_munmap(child, syscall, map.start(), map.size())?;
    }

    // println!("========== after delete:");
    // let maps = proc_maps::get_process_maps(child.as_raw() as proc_maps::Pid)?;
    // _print_maps_info(&maps[..]);

    loop {
        match bincode::deserialize_from::<&mut dyn Read, Command>(inp)? {
            Command::Mapping(m) => {
                if mmap_location >= m.addr && mmap_location < m.addr + m.size {
                    // TODO dodge or avoid this ahead of time
                    error("mapping to recreate collides with syscall page")?;
                }
                // println!("recreating {:?}", m);
                let addr = remote_mmap_anon(child, syscall, Some(m.addr), m.size, prot_all)?;
                // println!("recreated at {:?}", addr);
                // TODO set new area filenames
                stream_memory(child, inp, addr, m.size)?;
                // TODO remote mprotect to restore previous permissions
            }
            Command::ResumeWithRegisters { len } => {
                let mut reg_bytes = vec![0u8; len];
                inp.read_exact(&mut reg_bytes[..])?;
                // FIXME remove unwrap
                let reg_info = RegInfo::from_bytes(&reg_bytes[..]).unwrap();
                ptrace::setregs(child, reg_info.regs)?;
                // TODO resume
                break;
            }
        }
    }

    // println!("========== recreated maps:");
    // let maps = proc_maps::get_process_maps(child.as_raw() as proc_maps::Pid)?;
    // _print_maps_info(&maps[..]);

    // TODO remote mremap vdso stuff
    // TODO restore registers
    // TODO maybe jump to right place or maybe I can just restore rip
    // TODO resume
    ptrace::cont(child, None)?;

    Ok(child)
}

pub fn wait_for_exit(child: Pid) -> Result<i32> {
    match waitpid(child, None)? {
        WaitStatus::Exited(_, code) => Ok(code),
        _ => error("somehow got other wait status instead of exit"),
    }
}
