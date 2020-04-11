use telefork::{telepad, wait_for_exit};

use std::net::{TcpListener, TcpStream};

fn handle_client(mut stream: TcpStream) {
    let child = telepad(&mut stream).unwrap();
    println!("TELESERVER: received child to pid = {}", child);
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
