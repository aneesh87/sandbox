# sandbox
OS Sandbox

This is a sandbox for Unix/Linux developed using ptrace system call.When a program is under sandbox control, it can block access to user specified list of system calls.The ptrace system call monitors each and every system calls issued by program and checks if any listed calls are being called. It wiill catch such system calls and block them and set errno as EPERM. The system calls can be specified using a configuration file.
