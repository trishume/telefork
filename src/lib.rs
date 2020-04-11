use std::error::Error;
// use std::ffi::c_void;
use std::io::{Read, Write};

use libc;
use libc::{PROT_EXEC, PROT_READ, PROT_WRITE};

use nix;
use nix::errno::Errno;
use nix::sys::ptrace;
use nix::sys::signal::{kill, Signal};
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
struct ProcessState {
    brk_addr: usize,
}

#[derive(Serialize, Deserialize)]
enum Command {
    ProcessState(ProcessState),
    Mapping(Mapping),
    Remap {
        name: String,
        addr: usize,
        size: usize,
    },
    ResumeWithRegisters {
        len: usize,
    },
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
    false
}

fn error<T>(s: &'static str) -> Result<T> {
    Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, s)))
}

fn write_special_kernel_map(out: &mut dyn Write, map: &proc_maps::MapRange) -> Result<()> {
    let comm = Command::Remap {
        name: map
            .filename()
            .clone()
            .expect("can't be a kernel map without a name"),
        addr: map.start(),
        size: map.size(),
    };
    bincode::serialize_into::<&mut dyn Write, Command>(out, &comm)?;
    return Ok(());
}

fn write_regular_map(out: &mut dyn Write, child: Pid, map: &proc_maps::MapRange) -> Result<()> {
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

fn write_state(out: &mut dyn Write, child: Pid, proc_state: ProcessState) -> Result<()> {
    bincode::serialize_into::<&mut dyn Write, Command>(out, &Command::ProcessState(proc_state))?;

    let maps = proc_maps::get_process_maps(child.as_raw() as proc_maps::Pid)?;
    // _print_maps_info(&maps);

    // we write out special kernel maps like the vdso first so that we can remap them
    // to their correct position before some other regular map perhaps stomps on their
    // original position.
    let (special_maps, regular_maps) = maps
        .into_iter()
        .filter(|m| !should_skip_map(&m))
        .partition::<Vec<proc_maps::MapRange>, _>(|m| is_special_kernel_map(&m));

    for map in &special_maps {
        write_special_kernel_map(out, map)?;
    }
    for map in &regular_maps {
        write_regular_map(out, child, map)?;
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
    Woke(i32),
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
            // println!("hello from forked child!");
            kill_me_if_parent_dies()?;
            ptrace::traceme()?;
            // TODO is there a better way to pass a number along? This fails to detect if the raise syscall failed
            let raise_result = unsafe { libc::raise(libc::SIGSTOP) };
            Ok(NormalForkLocation::Woke(raise_result))
        }
    }
}

#[derive(Debug)]
pub enum TeleforkLocation {
    Parent,
    Child(i32),
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
    // println!("teleforking");
    let proc_state = ProcessState {
        // sbrk(0) returns current brk address and it won't change for child since we don't malloc before forking
        brk_addr: unsafe { libc::sbrk(0) as usize },
    };
    // println!("brk addr: {:>16x}", proc_state.brk_addr);
    let child: Pid = match fork_frozen_traced()? {
        NormalForkLocation::Woke(v) => return Ok(TeleforkLocation::Child(v)),
        NormalForkLocation::Parent(p) => p,
    };
    write_state(out, child, proc_state)?;

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

fn remote_brk(child: Pid, syscall: SyscallLoc, brk: usize) -> Result<usize> {
    let SyscallLoc(loc) = syscall;
    let regs = ptrace::getregs(child)?;
    let syscall_regs = libc::user_regs_struct {
        rip: loc as u64, // syscall instr
        rax: 12,         // munmap
        rdi: brk as u64, // addr
        ..regs
    };
    ptrace::setregs(child, syscall_regs)?;
    single_step(child)?;
    let new_regs = ptrace::getregs(child)?;
    Ok(new_regs.rax as usize)
}

fn remote_mremap(
    child: Pid,
    syscall: SyscallLoc,
    addr: usize,
    length: usize,
    new_addr: usize,
) -> Result<()> {
    if addr == new_addr {
        return Ok(());
    }

    let SyscallLoc(loc) = syscall;
    let regs = ptrace::getregs(child)?;
    let syscall_regs = libc::user_regs_struct {
        rip: loc as u64,                                         // syscall instr
        rax: 25,                                                 // mremap
        rdi: addr as u64,                                        // addr
        rsi: length as u64,                                      // old_length
        rdx: length as u64,                                      // new_length
        r10: (libc::MREMAP_MAYMOVE | libc::MREMAP_FIXED) as u64, // flags
        r8: new_addr as u64,                                     // new_addr
        ..regs
    };
    ptrace::setregs(child, syscall_regs)?;
    single_step(child)?;
    let new_regs = ptrace::getregs(child)?;
    if new_regs.rax as i64 == -1 {
        error("failed to mremap")?;
    }
    if new_regs.rax as usize != new_addr {
        // println!("remapped to {:x} from {:x} instead of {:x}", new_regs.rax, addr, new_addr);
        error("didn't mremap to correct location")?;
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

fn try_to_find_syscall(child: Pid, addr: usize) -> Result<usize> {
    let mut buf = vec![0u8; PAGE_SIZE];
    let wrote = uio::process_vm_readv(
        child,
        &[uio::IoVec::from_mut_slice(&mut buf[..])],
        &[uio::RemoteIoVec {
            base: addr,
            len: PAGE_SIZE,
        }],
    )?;
    if wrote == 0 {
        return error("failed to read from other process");
    }

    let syscall = &[0x0f, 0x05];
    match buf.windows(syscall.len()).position(|w| w == syscall) {
        Some(index) => Ok(index),
        None => error("couldn't find syscall"),
    }
}

fn find_map_named<'a>(
    maps: &'a [proc_maps::MapRange],
    name: &str,
) -> Option<&'a proc_maps::MapRange> {
    maps.iter().find(|map| match map.filename() {
        Some(n) if n == name => true,
        _ => false,
    })
}

fn restore_brk(child: Pid, syscall: SyscallLoc, brk_addr: usize) -> Result<()> {
    // TODO according to DMTCP this is the procedure that should work, but in
    // my testing it doesn't if the target brk is below the original heap,
    // then brk just doesn't update the heap. The way to fix this that also
    // restores a bunch of other things is to use PR_SET_MM_MAP but that's not
    // always available, requires high permissions, and it's hard to source
    // all the fields for that. In the case that it fails this implementation
    // is basically the same as not restoring the brk at all.

    let orig_brk = remote_brk(child, syscall, 0)?;
    // Is it possible that changing the brk could munmap the vdso? I think not with default layouts but maybe wrong.
    let new_brk = remote_brk(child, syscall, brk_addr)?;

    // println!("brk orig={:>16x} new={:>16x} target={:>16x}", orig_brk, new_brk, brk_addr);
    if new_brk > orig_brk {
        // we mapped a new region but we want everything cleared away still so munmap it
        remote_munmap(child, syscall, orig_brk, new_brk - orig_brk)?;
    }

    Ok(())
}

pub fn telepad(inp: &mut dyn Read, pass_to_child: i32) -> Result<Pid> {
    // println!("incoming on telepad");
    let child: Pid = match fork_frozen_traced()? {
        NormalForkLocation::Woke(_) => panic!("should've woken up with my brain replaced but didn't!"),
        NormalForkLocation::Parent(p) => p,
    };

    let orig_maps = proc_maps::get_process_maps(child.as_raw() as proc_maps::Pid)?;
    // _print_maps_info(&orig_maps[..]);

    let vdso_map = find_map_named(&orig_maps, "[vdso]").unwrap();
    let vdso_syscall_offset = try_to_find_syscall(child, vdso_map.start())?;
    let mut vdso_syscall = SyscallLoc((vdso_map.start() + vdso_syscall_offset) as u64);

    // ==== remote munmap all original regions except vdso stuff
    for map in &orig_maps {
        if is_special_kernel_map(map) || map.size() == 0 {
            continue;
        }
        // println!("unmapping {:?}", map);
        remote_munmap(child, vdso_syscall, map.start(), map.size())?;
    }

    let maps = proc_maps::get_process_maps(child.as_raw() as proc_maps::Pid)?;
    // println!("========== after delete:");
    // _print_maps_info(&maps[..]);

    let prot_all = PROT_READ | PROT_WRITE | PROT_EXEC;
    loop {
        match bincode::deserialize_from::<&mut dyn Read, Command>(inp)? {
            Command::ProcessState(ProcessState { brk_addr }) => {
                restore_brk(child, vdso_syscall, brk_addr)?;
            }
            Command::Remap { name, addr, size } => {
                let matching_map = find_map_named(&maps, &name).unwrap();

                // TODO on my NixOS box the VDSO is a different size than my Docker container
                // this may just be a case that's nigh-impossible to handle fully correctly or I'm missing a trick

                if size != matching_map.size() {
                    // error("size mismatch in remap")?;
                    eprintln!("size mismatch in remap for {}", name);
                }

                // println!("remapping {:?}", matching_map);
                remote_mremap(
                    child,
                    vdso_syscall,
                    matching_map.start(),
                    matching_map.size(),
                    addr,
                )?;

                if &name == "[vdso]" {
                    vdso_syscall = SyscallLoc((addr + vdso_syscall_offset) as u64);
                    // println!("changing vdso syscall to {:x}", vdso_syscall.0);
                }
            }
            Command::Mapping(m) => {
                // println!("recreating {:?}", m);
                let addr = remote_mmap_anon(child, vdso_syscall, Some(m.addr), m.size, prot_all)?;
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
                let mut regs = reg_info.regs;
                // We'll be resuming from the "raise" syscall which checks for an i32 result in rax and libc passes along
                regs.rax = pass_to_child as u64;
                ptrace::setregs(child, regs)?;
                break;
            }
        }
    }

    // TODO maybe use /proc/sys/kernel/ns_last_pid to restore with the same PID if possible? http://efiop-notes.blogspot.com/2014/06/how-to-set-pid-using-nslastpid.html
    // TODO restore TLS: This seems to involve using the arch_prcntl syscall to save and restore the FS and GS registers
    // ptrace does save/restore fs and gs though and TLS variables appear to work to me so maybe that isn't necessary?
    // There's also something about how glibc caches the pid and tid which are wrong in the new process.

    // TODO support using the vDSO of a different Linux kernel. Currently it
    // just assumes the vDSO is the same and the program crashes if it tries
    // to use the vDSO and it isn't the same. One idea for how to fix this is
    // to do like rr (https://github.com/mozilla/rr/issues/1216) and put jump
    // patches at all the entry points from the orginal processes's vDSO that
    // jump to the correct places in the new vDSO as determined by reading the
    // vDSO ELF header.

    // TODO restore or forward some types of file descriptors? Maybe basic files that also exist on the new system?

    // println!("========== recreated maps:");
    // let maps = proc_maps::get_process_maps(child.as_raw() as proc_maps::Pid)?;
    // _print_maps_info(&maps[..]);

    ptrace::detach(child, None)?;

    Ok(child)
}

pub fn wait_for_exit(child: Pid) -> Result<i32> {
    match waitpid(child, None)? {
        WaitStatus::Exited(_, code) => Ok(code),
        status => {
            eprintln!("wait got: {:?}", status);
            error("somehow got other wait status instead of exit")
        }
    }
}

use std::net::{TcpStream, ToSocketAddrs};
use std::os::unix::io::FromRawFd;

// teleforks to a teleserver compatible server, executes `f`, then receives a
// telefork back. Only returns in the new process that is teleforked back on
// the client, the original process waits for its child to exit then exits
// with the same status.
pub fn yoyo<A: ToSocketAddrs, F: FnOnce() -> ()>(dest: A, f: F) {
    let mut stream = TcpStream::connect(dest).unwrap();
    let loc = telefork(&mut stream).unwrap();
    match loc {
        TeleforkLocation::Child(fd) => {
            let mut stream = unsafe { TcpStream::from_raw_fd(fd) };

            // Do some work on the remote server
            f();

            let loc = telefork(&mut stream).unwrap();
            std::mem::forget(stream); // parent drops stream not us
            match loc {
                // return normally in the child we teleforked back
                TeleforkLocation::Child(_) => return,
                // exit succesfully in the now unnecessary server process
                TeleforkLocation::Parent => std::process::exit(0),
            };
        }
        // teleforked succesfully, return out of match statement and wait to receive telefork back
        TeleforkLocation::Parent => (),
    };

    // receive the telefork back
    let child = telepad(&mut stream, 0).unwrap();
    // we don't return from this function in the original process, we let it
    // return in the newly received process then just wait and exit with the
    // same status
    let status = wait_for_exit(child).unwrap();
    std::process::exit(status);
}
