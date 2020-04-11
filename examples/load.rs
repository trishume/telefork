use telefork::{telepad, wait_for_exit};

use std::fs::File;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let fname = &args[1];
    println!("loading from {:?}", fname);
    let mut input = File::open(fname).unwrap();
    let child = telepad(&mut input, 1).unwrap();
    println!("child pid = {}", child);
    let status = wait_for_exit(child).unwrap();
    println!("child exited with status = {}", status);
}
