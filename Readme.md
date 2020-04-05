# telefork

I intend for this project to be somewhat hiding in plain sight until I get
around to writing a blog post about it.

Basically it's like the fork() syscall except it can fork a process onto a
different computer. It does this using a bunch of ptrace magic to serialize
the memory mappings of the process, stream them over a pipe and recreate them
on the other end along with the registers and some other process state.

If you don't want to wait for the blog post or I never get around to writing
the blog post, there's fairly little code and some comments and naming so you
might be able to follow along by reading it and find it cool.
