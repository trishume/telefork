use telefork::telefork;

use std::fs::File;

fn main() {
    println!("Hello!");
    let foo = 7;
    let mut output = File::create("dump.telefork.bin").unwrap();
    let loc = telefork(&mut output).unwrap();
    println!("loc = {:?} foo = {}", loc, foo);
}
