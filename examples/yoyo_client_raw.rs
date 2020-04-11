use telefork::{telefork, telepad, wait_for_exit, TeleforkLocation};

use std::net::{TcpStream};
use std::os::unix::io::FromRawFd;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let destination = args.get(1).expect("expected arg: address of teleserver");

    println!("Hello, I'm a process that's about to telefork myself onto a server!");
    let mut foo = 103;
    println!("I have a local variable that says foo={}", foo);
    let mut stream = TcpStream::connect(destination).unwrap();
    let loc = telefork(&mut stream).unwrap();
    match loc {
        TeleforkLocation::Child(fd) => {
            let mut stream = unsafe { TcpStream::from_raw_fd(fd) };
            println!("I'm a process that teleported itself to a different computer");
            println!("My local variable says foo={} and I'm going to exit with that status", foo);

            // Do some work on the remote server
            foo = 42;

            let loc = telefork(&mut stream).unwrap();
            std::mem::forget(stream); // parent drops stream not us
            match loc {
                TeleforkLocation::Child(_) => {
                    println!("Arrived back on client machine with foo={}", foo);
                }
                TeleforkLocation::Parent => println!("teleforked result process back to client!"),
            };
            std::process::exit(0);
        }
        TeleforkLocation::Parent => println!("I succesfully teleforked myself!"),
    };

    let child = telepad(&mut stream, 0).unwrap();
    println!("got child back with pid = {}", child);
    let status = wait_for_exit(child).unwrap();
    println!("child exited with status = {}", status);

    // let mut got_back = String::new();
    // let bytes_read = stream.read_to_string(&mut got_back).unwrap();
    // println!("read {} bytes: {:?}", bytes_read, got_back);
}
