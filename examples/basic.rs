use telefork::{telefork, telepad, wait_for_exit, TeleforkLocation};

use std::fs::File;

fn main() {
    println!("Hello!");
    let foo = 103;
    let fname = "dump.telefork.bin";
    let loc = {
        let mut output = File::create(fname).unwrap();
        telefork(&mut output).unwrap()
    };
    match loc {
        TeleforkLocation::Child => {
            println!("hello from a strange new world where foo={}", foo);
            std::process::exit(foo)
        }
        TeleforkLocation::Parent => println!("finished teleforking"),
    };
    let mut input = File::open(fname).unwrap();
    let child = telepad(&mut input).unwrap();
    println!("child pid = {}", child);
    let status = wait_for_exit(child).unwrap();
    println!("child exited with status = {}", status);
}
