use telefork::{telefork, TeleforkLocation};

use std::net::{TcpStream};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let destination = args.get(1).expect("expected arg: address of teleserver");

    println!("Hello, I'm a process that's about to telefork myself onto a server!");
    let foo = 103;
    println!("I have a local variable that says foo={}", foo);
    let loc = {
        let mut stream = TcpStream::connect(destination).unwrap();
        telefork(&mut stream).unwrap()
    };
    match loc {
        TeleforkLocation::Child => {
            println!("I'm a process that teleported itself to a different computer");
            println!("My local variable says foo={} and I'm going to exit with that status", foo);
            std::process::exit(foo);
        }
        TeleforkLocation::Parent => println!("I succesfully teleforked myself!"),
    };
}
