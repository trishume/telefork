use telefork::{telepad, wait_for_exit};

use std::net::{TcpListener, TcpStream};
use std::os::unix::io::AsRawFd;

fn handle_client(mut stream: TcpStream) {
    println!("TELESERVER: starting to receive process!");
    let fd = stream.as_raw_fd() as i32;
    let child = telepad(&mut stream, fd).unwrap();
    println!(
        "TELESERVER: received child to pid = {} and passed TCP fd={}",
        child, fd
    );
    let status = wait_for_exit(child).unwrap();
    println!("TELESERVER: child exited with status = {}", status);
}

fn main() -> std::io::Result<()> {
    let listener = TcpListener::bind("0.0.0.0:7335")?;
    println!("TELESERVER: Listening for clients on 0.0.0.0:7335!");
    for stream in listener.incoming() {
        handle_client(stream?);
    }
    Ok(())
}
