use std::error::Error;
use std::io::Write;

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
}

fn should_skip_map(map: &proc_maps::MapRange) -> bool {
    // TODO handle non-library read-only things by remapping as readable
    // TODO or maybe preserve them without contents and map zero pages on rehydrate
    if !map.is_read() || map.size() == 0 {
        return true;
    }
    match map.filename() {
        Some(n) if (n == "[vdso]" || n == "[vsyscall]" || n == "[vvar]") => true,
        _ => false,
    }
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
    let mut buf = vec![0u8; 4096];
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

fn write_state(out: &mut dyn Write, child: Pid) -> Result<()> {
    let maps = proc_maps::get_process_maps(child.as_raw() as proc_maps::Pid)?;
    // print_maps_info(&maps);

    for map in &maps {
        write_map(out, child, map)?;
    }
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

fn print_maps_info(maps: &[proc_maps::MapRange]) {
    for map in maps {
        println!("{:>7} {:?}", map.size(), map.filename());
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
