use telefork::{telefork, telepad, TeleforkLocation};

use std::fs::File;

fn main() {
    println!("Hello!");
    let foo = 7;
    let fname = "dump.telefork.bin";
    let loc = {
        let mut output = File::create(fname).unwrap();
        telefork(&mut output).unwrap()
    };
    match loc {
        TeleforkLocation::Child => {
            println!("hello from a strange new world where foo={}", foo);
            return;
        }
        TeleforkLocation::Parent => println!("finished teleforking"),
    };
    let mut input = File::open(fname).unwrap();
    let child = telepad(&mut input).unwrap();
    println!("child pid = {}", child);
}
