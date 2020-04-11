use telefork::{telefork, telepad, wait_for_exit, TeleforkLocation};

use std::fs::File;

use std::sync::atomic::{AtomicU32, Ordering};
// use nix::sys::signal::{raise, Signal};

thread_local! {
    static TEST_TLS : AtomicU32 = AtomicU32::new(7);
}

fn print_tls_val() {
    TEST_TLS.with(|t| println!("tls: {}", t.load(Ordering::SeqCst)));
}

fn main() {
    println!("Hello!");
    let foo = 103;
    let fname = "dump.telefork.bin";
    TEST_TLS.with(|t| t.store(4, Ordering::SeqCst));
    print_tls_val();
    let loc = {
        let mut output = File::create(fname).unwrap();
        telefork(&mut output).unwrap()
    };
    match loc {
        TeleforkLocation::Child(val) => {
            // raise(Signal::SIGSTOP).unwrap();
            // std::process::exit(foo);
            println!("hello from a strange new world where I woke up passed {}", val);
            println!("My local variable says foo={} and I'm going to exit with that status", foo);

            // I'm somewhat confused about why TLS seems to me to just work.
            // ptrace register setting seems to include the fs and gs
            // registers, but I thought that I would need to use arch_prctl to
            // set what Linux thinks they should be so they don't get
            // overwritten with the wrong things when a thread swaps back in.
            print_tls_val();

            std::thread::sleep(std::time::Duration::from_millis(100));
            print_tls_val();
            std::process::exit(foo)
        }
        TeleforkLocation::Parent => println!("finished teleforking"),
    };
    let mut input = File::open(fname).unwrap();
    let child = telepad(&mut input, 7).unwrap();
    println!("child pid = {}", child);
    let status = wait_for_exit(child).unwrap();
    println!("child exited with status = {}", status);
}
