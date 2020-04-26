# telefork

Check out [the blog post I wrote about this project](https://thume.ca/2020/04/18/telefork-forking-a-process-onto-a-different-computer/)!

Basically it's like the `fork()` syscall except it can fork a process onto a
different computer. It does this using a bunch of ptrace magic to serialize
the memory mappings of the process, stream them over a pipe and recreate them
on the other end along with the registers and some other process state.

# How it works

Read the code in `src/lib.rs!`. I specifically wrote it all in **one file with
tons of comments** in an order meant to read top to bottom. Hopefully it should
be easy enough to understand what it's doing, provided some familiarity with
systems programming concepts.

# Examples

- `basic` and `load`: Save and restore a process state to a file
- `teleserver` and `teleclient`: Fork a process to a remote server
- `yoyo_client` and `yoyo_client_raw`: Execute a closure on a remote server by teleforking there and back
- `smallpt`: Use `yoyo` to run a path tracing render on a remote server from a local executable.
