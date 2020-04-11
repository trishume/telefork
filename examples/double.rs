use telefork::{telefork, telepad, wait_for_exit, TeleforkLocation};

use std::fs::File;

fn main() {
    println!("Hello!");
    let mut foo = 103;
    let fname = "dump.telefork.bin";
    let loc = {
        let mut output = File::create(fname).unwrap();
        telefork(&mut output).unwrap()
    };
    match loc {
        TeleforkLocation::Child(val) => {
            println!("hello after first telefork where val={} and foo={}", val, foo);
            foo = 42;
            let loc = {
                let mut output = File::create("dump2.telefork.bin").unwrap();
                telefork(&mut output).unwrap()
            };
            match loc {
                TeleforkLocation::Child(val) => {
                    println!("hello after second telefork where val={} and foo={}", val, foo);
                }
                TeleforkLocation::Parent => println!("finished second telefork to file"),
            };
            std::process::exit(foo);
        }
        TeleforkLocation::Parent => println!("finished teleforking"),
    };
    let mut input = File::open(fname).unwrap();
    let child = telepad(&mut input, 5).unwrap();
    println!("child pid = {}", child);
    let status = wait_for_exit(child).unwrap();
    println!("child exited with status = {}", status);
}
