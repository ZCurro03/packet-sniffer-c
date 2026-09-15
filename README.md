# C Packet Sniffer

A custom, low-level packet sniffer developed in C using the `libpcap` library. This project captures network traffic in real-time and performs deep packet inspection by parsing headers across multiple OSI layers (Ethernet, IPv4, TCP/UDP).

Built as a hands-on cybersecurity and systems engineering project to deepen understanding of network protocols, raw memory management, and socket-level programming.

## Prerequisites

To compile and run this project, you will need the following dependencies installed on your system:
* GCC: The GNU Compiler Collection.
* Make: Build automation tool.
* libpcap: Packet capture library (e.g., `libpcap-dev` on Debian/Ubuntu).
* Valgrind: (Optional) For memory leak detection and profiling.

## Compilation

This project includes a `Makefile` to streamline the build process. Navigate to the root directory of the project and use the following commands:
* `make compile`: Compiles the source code and generates the `sniffer` executable.
* `make clean`: Removes the intermediate object files (`.o`) from the `obj/` directory.
* `make full_clean`: Removes both the object files and the final `sniffer` executable.

## Usage

Because packet sniffing requires putting the network interface into promiscuous mode and accessing raw sockets, the operating system restricts this action to privileged users. You have two options to run the program:

**Option 1: Using sudo (Standard)**

The simplest way to run the sniffer is with root privileges. You can use the Makefile wrapper or run the binary directly:
* `sudo make run`
* `sudo ./sniffer`

**Option 2: Using Linux Capabilities (Secure & No Sudo)**

If you prefer not to run the program as root, you can grant the specific network capabilities to the compiled binary. This allows any standard user to execute it:
* Compile the program: `make compile`
* Grant raw network capabilities: `sudo setcap cap_net_raw,cap_net_admin=eip sniffer`
* Run as a normal user: `./sniffer`

## Debugging

To run the sniffer through Valgrind to check for memory leaks (requires root privileges if capabilities are not set):
* `sudo make run_v`
