use telefork::{telefork, TeleforkLocation};

use std::net::{TcpStream};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let destination = args.get(1).expect("expected arg: address of teleserver");

    println!("Hello!");
    let foo = 103;
    let loc = {
        let mut stream = TcpStream::connect(destination).unwrap();
        telefork(&mut stream).unwrap()
    };
    match loc {
        TeleforkLocation::Child => {
            println!("I'm a process that teleported itself to a different computer where foo={}", foo);
        }
        TeleforkLocation::Parent => println!("finished teleforking"),
    };
}
