fn main() {
    let args: Vec<String> = std::env::args().collect();
    let destination = args.get(1).expect("expected arg: address of teleserver");

    let mut foo = 103;
    println!("there are {} cpus on the client", num_cpus::get());
    println!("we currently have foo={}, now we yoyo to the server", foo);
    telefork::yoyo(destination, || {
        println!("now on the server we modify foo");
        println!("there are {} cpus on the server", num_cpus::get());
        foo = 42;
        println!("set foo={} on the server and returning back", foo);
    });
    println!("back on the original client we now have foo={}", foo);
}
