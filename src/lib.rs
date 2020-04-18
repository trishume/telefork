//! A fun technical joke allowing you to `telefork` a process to a different
//! computer. This is more a tech demo than a real library, I don't actually
//! recommend you use it for anything real at least not without reading the
//! code and noting all the TODO comments for things that aren't handled
//! correctly.
//!
//! I tried to order and comment the source code so that reading this file top
//! to bottom is a good way to understand how it works. This is also why it's
//! all in one module, because I can't make a good reading order across modules.

// The nix crate iis a handy Rust-ified wrapper over libc stuff
use nix;
use nix::errno::Errno;
use nix::sys::ptrace;
use nix::sys::signal::{kill, Signal};
use nix::sys::uio;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{ForkResult, Pid};

// But not everything we want to use has a nix wrapper
use libc;
use libc::{PROT_EXEC, PROT_READ, PROT_WRITE};

// Handy crate to inspect process memory maps
use proc_maps;

// We use these to serialize our state over the wire
use bincode;
use serde::{Deserialize, Serialize};

// Error handling
use std::error::Error;
use std::io::{Read, Write};

// Used for the `yoyo` helper at the bottom
use std::net::{TcpStream, ToSocketAddrs};
use std::os::unix::io::FromRawFd;


type Result<T> = std::result::Result<T, Box<dyn Error>>;
const PAGE_SIZE: usize = 4096;

// In order to do the path tracing demo to a remote server with a different
// kernel I really just wanted to get it to work even though it used the vDSO.
// I did this by just overriding it to teleport the vDSO contents anyways
// instead of remapping. The issue is I have no idea how the vDSO actually
// interacts with the kernel so this might totally not work. Also I don't
// properly handle the case where mappings collide and the existing and new
// map vDSO might overlap. This setting enables this janky vDSO support.
const JANKY_VDSO_TELEPORT: bool = false;

#[derive(Debug)]
pub enum TeleforkLocation {
    Parent,
    /// the i32 is just a piece of info the telepad can pass to the process it's waking up.
    /// for example it could be a file descriptor to communicate with the parent.
    Child(i32),
}

/// The `telefork` function streams the current process's state over a writeable channel
pub fn telefork(out: &mut dyn Write) -> Result<TeleforkLocation> {
    // == 1. Record anything we can easily record within our own process
    let proc_state = ProcessState {
        // sbrk(0) returns current brk address and it won't change for child since we don't malloc before forking
        brk_addr: unsafe { libc::sbrk(0) as usize },
    };
    // == 2. Fork our process into a frozen child that we can ptrace and inspect
    // without it changing. If we try to inspect ourselves we'll run into
    // problems where our registers and stack are changing as we're
    // serializing.
    let child: Pid = match fork_frozen_traced()? {
        // On the other end the process will be restarted from its frozen
        // state and return thinking its a forked child to this point, so
        // return from telefork notifying we're on the other end.
        NormalForkLocation::Woke(v) =>
            return Ok(TeleforkLocation::Child(v)),
        NormalForkLocation::Parent(p) => p,
    };
    // == 3. Inspect all the pieces of state and stream them out
    write_state(out, child, proc_state)?;
    // == 4. Now that we're done reading it we no longer need the forked child and we can return
    kill(child, Signal::SIGKILL)?;
    // == 5. We're the parent, return normally saying so
    Ok(TeleforkLocation::Parent)
}

// === 2. Fork our process into a frozen child
enum NormalForkLocation {
    Parent(Pid),
    Woke(i32),
}

fn fork_frozen_traced() -> Result<NormalForkLocation> {
    match nix::unistd::fork()? {
        ForkResult::Parent { child, .. } => match waitpid(child, None)? {
            WaitStatus::Stopped(_, Signal::SIGSTOP) => Ok(NormalForkLocation::Parent(child)),
            _ => error("couldn't trace child"),
        },
        ForkResult::Child => {
            // This is handy so that when I break things and crash the parent I don't get processes sticking around
            kill_me_if_parent_dies()?;
            // This lets the parent inspect our state even if they normally wouldn't have sufficient permissions
            ptrace::traceme()?;
            // Use a raise syscall to stop our process, when rehydrated we'll
            // be resumed from this syscall with a doctored return value
            //
            // TODO is there a better way to pass a number along? This fails
            // to detect if the raise syscall failed
            let raise_result = unsafe { libc::raise(libc::SIGSTOP) };
            Ok(NormalForkLocation::Woke(raise_result))
        }
    }
}

fn kill_me_if_parent_dies() -> nix::Result<()> {
    let res = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) };
    Errno::result(res).map(|_| ())
}

// ==== 3. Inspect all pieces of the state and stream them out

/// We want to stream the state as opposed to doing it all at once so we do it
/// as a series of commands to restore specific pieces, rather than one big
/// data structure.
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

/// Most of the state is composed of memory mappings
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

/// Some state that we can safely and more easily read before forking
#[derive(Serialize, Deserialize)]
struct ProcessState {
    brk_addr: usize,
}

/// Some maps are not safe/a good idea to serialize and teleport to the remote process, we try to remap them instead
fn is_special_kernel_map(map: &proc_maps::MapRange) -> bool {
    match map.filename() {
        Some(n) if (n == "[vdso]" || n == "[vsyscall]" || n == "[vvar]") => true,
        _ => false,
    }
}

/// It turns out that even remapping them doesn't work across different kernel
/// builds so given a flag we can try teleporting them anyways. This worked in
/// my experience in a case where the kernel version was the same but the
/// builds/distros were different so remapping segfaulted.
fn should_teleport_kernel_map_anyways(map: &proc_maps::MapRange) -> bool {
    if !JANKY_VDSO_TELEPORT {
        return false;
    }
    match map.filename() {
        Some(n) if n == "[vdso]" => true,
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

/// Handy crappy utility to make it easier to raise custom errors. If this was for real I'd use the `anyhow` crate.
fn error<T>(s: &'static str) -> Result<T> {
    Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, s)))
}

/// We still need to record the expected location of special maps
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

/// Record a normal memory map's info and then stream its contents over the output channel
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

    // === write contents to output channel a page at a time
    let mut remaining_size = map.size();
    let mut buf = vec![0u8; PAGE_SIZE];
    while remaining_size > 0 {
        let read_size = std::cmp::min(buf.len(), remaining_size);
        let offset = map.start() + (map.size() - remaining_size);

        // This is a rare special syscall to copy memory from another process
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
        out.write(&buf[..])?;
        remaining_size -= read_size;
    }

    Ok(())
}

/// Serialized registers
///
/// NOTE I think this might break if you use a different build of telefork on
/// the destination that was compiled with a sufficiently different libc
#[repr(C)]
struct RegInfo {
    pub regs: libc::user_regs_struct,
}

/// Be incredibly lazy with implementing proper serialization routines and
/// just splat the raw bytes to and from the stream in a very unsafe
/// non-Rust-y way because this is a tech demo I did for fun on a weekend.
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

/// Write out each piece of state in the ideal order using the above functions
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
        .partition::<Vec<proc_maps::MapRange>, _>(|m| {
            is_special_kernel_map(&m) && !should_teleport_kernel_map_anyways(&m)
        });

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

// === Child process manipulation utilities
//
// In order to restore the serialized process we need various tools to mold an
// existing process into a rehydrated clone of the serialized process.

/// Print a representation of the mappings of a process
///
/// Prefixed with an underscore because I normally don't use this, but I often
/// uncomment a line that does use it for debugging.
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

/// Advance the child process by one instruction. This is used to execute
/// syscall instructions in the child process.
fn single_step(child: Pid) -> Result<()> {
    ptrace::step(child, None)?;
    match waitpid(child, None)? {
        WaitStatus::Stopped(_, Signal::SIGTRAP) => Ok(()),
        _ => error("couldn't single step child"),
    }
}

/// Wrapper to signify that we've verified a given memory offset in the child
/// as containing a syscall instruction we can use by manipulating the
/// instruction pointer to point to it, putting the arguments in registers,
/// and then single stepping.
#[derive(Copy, Clone)]
struct SyscallLoc(u64);

/// We find these syscalls by searching for an existing syscall instruction
/// inside a page in the child process. One can always be found (as far as I
/// know) by passing the address of `[vdso]` as the `addr`.
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

// The simplest case of a remote syscall
fn remote_brk(child: Pid, syscall: SyscallLoc, brk: usize) -> Result<usize> {
    let SyscallLoc(loc) = syscall;
    // == 1. Get the current register state so we can modify
    let regs = ptrace::getregs(child)?;
    // == 2. Modify only the registers involved in the syscall
    let syscall_regs = libc::user_regs_struct {
        rip: loc as u64, // syscall instr (rip is the instruction pointer)
        rax: 12,         // munmap (rax holds the syscall number)
        rdi: brk as u64, // addr (first argument to syscall goes in rdi)
        ..regs
    };
    // == 2. Set the modified regs
    ptrace::setregs(child, syscall_regs)?;
    // == 3. Execute the syscall instruction (we set rip to point to it)
    single_step(child)?;
    // == 4. Get the instructions so we can extract the return value from rax
    let new_regs = ptrace::getregs(child)?;
    Ok(new_regs.rax as usize)
}

// The most complex case of a remote syscall, but basically the same
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
        // Caller requested a specific address
        Some(addr) => (addr, flags | libc::MAP_FIXED),
        // No specific address requested, we just want to map anywhere available
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

/// The inverse of the streaming in `write_regular_map`. Streams memory from a
/// `Read` channel into a child process at a certain address.
fn stream_memory(child: Pid, inp: &mut dyn Read, addr: usize, length: usize) -> Result<()> {
    let mut remaining_size = length;
    let mut buf = vec![0u8; PAGE_SIZE];
    while remaining_size > 0 {
        let batch_size = std::cmp::min(buf.len(), remaining_size);
        let offset = addr + (length - remaining_size);

        inp.read_exact(&mut buf[..batch_size])?;

        // The inverse of the earlier rare syscall, copies to a child's memory
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

/// Helper to find a map with a specific name, used to match up special kernel maps
fn find_map_named<'a>(
    maps: &'a [proc_maps::MapRange],
    name: &str,
) -> Option<&'a proc_maps::MapRange> {
    maps.iter().find(|map| match map.filename() {
        Some(n) if n == name => true,
        _ => false,
    })
}

/// The brk pointer is an old school syscall that at least used to be used for
/// expanding/contracting the `[heap]` memory mapping. It's one of the pieces
/// of process state stored outside of memory and registers. I don't *think*
/// it's used by modern heap allocation but I'm not sure.
///
/// It's hard to manipulate. This doesn't actually work a lot of the time. It
/// probably doesn't really matter for many programs.
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

/// The other end of a `telefork`. Receive a program from a read channel and
/// rehydrate it as a child process, passing it an i32 and return its pid.
pub fn telepad(inp: &mut dyn Read, pass_to_child: i32) -> Result<Pid> {
    // == 1. Create a frozen child to hollow out and replace with the process being streamed in
    let child: Pid = match fork_frozen_traced()? {
        NormalForkLocation::Woke(_) => {
            panic!("should've woken up with my brain replaced but didn't!")
        }
        NormalForkLocation::Parent(p) => p,
    };

    // == 2. Inspect the state of the child so we can manipulate it to hollow it out
    let orig_maps = proc_maps::get_process_maps(child.as_raw() as proc_maps::Pid)?;
    // _print_maps_info(&orig_maps[..]);

    // The vdso always seems to have a syscall in it we can use for remote syscalls
    let vdso_map = find_map_named(&orig_maps, "[vdso]").unwrap();
    let vdso_syscall_offset = try_to_find_syscall(child, vdso_map.start())?;
    let mut vdso_syscall = SyscallLoc((vdso_map.start() + vdso_syscall_offset) as u64);

    // == 3. Remote munmap all original regions except special kernel stuff
    for map in &orig_maps {
        if is_special_kernel_map(map) || map.size() == 0 {
            continue;
        }
        remote_munmap(child, vdso_syscall, map.start(), map.size())?;
    }

    let maps = proc_maps::get_process_maps(child.as_raw() as proc_maps::Pid)?;
    // println!("========== after delete:");
    // _print_maps_info(&maps[..]);

    // == 4. Now that it's hollowed out, start a loop to read restoration commands from the channel
    let prot_all = PROT_READ | PROT_WRITE | PROT_EXEC;
    loop {
        match bincode::deserialize_from::<&mut dyn Read, Command>(inp)? {
            Command::ProcessState(ProcessState { brk_addr }) => {
                restore_brk(child, vdso_syscall, brk_addr)?;
            }
            Command::Remap { name, addr, size } => {
                let matching_map = find_map_named(&maps, &name);
                let matching_map = match matching_map {
                    Some(m) => m,
                    None => {
                        eprintln!("no matching map for {} so can't remap", name);
                        continue;
                    }
                };

                if size != matching_map.size() {
                    // Some Linux distros/versions seem to have 1 page vDSOs
                    // and some have 2 pages I made this a non-critical error
                    // so that you can telefork anyway and it might work,
                    // especially if the program doesn't use any vDSO
                    // syscalls. See later TODO comment on handling vDSOs.


                    // error("size mismatch in remap")?;
                    eprintln!("size mismatch in remap for {}", name);
                }

                remote_mremap(
                    child,
                    vdso_syscall,
                    matching_map.start(),
                    matching_map.size(),
                    addr,
                )?;

                // When we remap the vDSO we have to change the address we're
                // using for remote syscalls to the new location. It happens
                // to still work to use a syscall in the vDSO to mremap the
                // vDSO elsewhere even though it returns to unmapped space,
                // because ptrace stops it before it executes anything from
                // unmapped space.
                if &name == "[vdso]" {
                    vdso_syscall = SyscallLoc((addr + vdso_syscall_offset) as u64);
                }
            }
            Command::Mapping(m) => {
                let addr = remote_mmap_anon(child, vdso_syscall, Some(m.addr), m.size, prot_all)?;
                // TODO set new area filenames
                stream_memory(child, inp, addr, m.size)?;
                // TODO remote mprotect to restore previous permissions
            }
            Command::ResumeWithRegisters { len } => {
                let mut reg_bytes = vec![0u8; len];
                inp.read_exact(&mut reg_bytes[..])?;
                // FIXME remove unwrap and use a proper error for bad serialization
                let reg_info = RegInfo::from_bytes(&reg_bytes[..]).unwrap();
                let mut regs = reg_info.regs;
                // We'll be resuming from the "raise" syscall which checks for an i32 result in rax and libc passes along
                regs.rax = pass_to_child as u64;
                ptrace::setregs(child, regs)?;
                break;
            }
        }
    }

    // TODO maybe use /proc/sys/kernel/ns_last_pid to restore with the same
    // PID if possible? This might help thread local storage and other things work better.
    // http://efiop-notes.blogspot.com/2014/06/how-to-set-pid-using-nslastpid.html

    // TODO restore TLS: This seems to involve using the arch_prcntl syscall
    // to save and restore the FS and GS registers ptrace does save/restore fs
    // and gs though and TLS variables appear to work to me so maybe that
    // isn't necessary? There's also something about how glibc caches the pid
    // and tid which are wrong in the new process.

    // TODO support using the vDSO of a different Linux kernel. Currently it
    // just assumes the vDSO is the same and the program crashes if it tries
    // to use the vDSO and it isn't the same. One idea for how to fix this is
    // to do like rr (https://github.com/mozilla/rr/issues/1216) and put jump
    // patches at all the entry points from the orginal processes's vDSO that
    // jump to the correct places in the new vDSO as determined by reading the
    // vDSO ELF header.
    //
    // Another possible solution is to do what rr does and patch all the vDSO
    // entry points to just execute the normal syscalls.

    // TODO restore or forward some types of file descriptors? Maybe basic
    // files that also exist on the new system?

    // println!("========== recreated maps:");
    // let maps = proc_maps::get_process_maps(child.as_raw() as proc_maps::Pid)?;
    // _print_maps_info(&maps[..]);

    // This lets the other process be stopped without triggering out waitpid,
    // as well as to be debugged by a different ptrace-er
    ptrace::detach(child, None)?;

    // Return the child pid so that we can do things or wait on it
    Ok(child)
}

/// Utility to wait for the child process to exit, which is often what you
/// want to do after using `telepad`.
pub fn wait_for_exit(child: Pid) -> Result<i32> {
    match waitpid(child, None)? {
        WaitStatus::Exited(_, code) => Ok(code),
        status => {
            eprintln!("wait got: {:?}", status);
            error("somehow got other wait status instead of exit")
        }
    }
}

// Helper that magically executes a closure on a remote server, perhaps one
// with way more processing power. See the `smallpt` example for a demo using
// this to do ray tracing on a larger remote server. The closure can access
// and modify any data in this process and after `yoyo` returns execution is
// back on the original machine.
//
// To do this it teleforks to a server like the `teleserver` example, executes
// closure `f`, then receives a telefork back. Only returns in the new process
// that is teleforked back on the client, the original process waits for its
// child to exit then exits with the same status.
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
