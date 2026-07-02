A Linux debugger for x86-64, written from scratch in C++. minidbg uses ptrace to control a running process, sets software breakpoints, inspects registers and memory, and parses ELF/DWARF debug info to map breakpoint hits back to source lines.

This project follows Sy Brand's "Writing a Linux Debugger" tutorial series as a base, extended and rewritten while working through the internals of process tracing, ELF/DWARF, and stack unwinding.

Features


Process control via ptrace — launches a target binary in a forked child, attaches with PTRACE_TRACEME, and drives execution (PTRACE_CONT, PTRACE_SINGLESTEP)
Software breakpoints — sets breakpoints by patching the target address with an int3 (0xCC) instruction and restoring the original byte on removal
Register access — read, write, and dump the full x86-64 general-purpose register set for the traced process
Memory access — read and write arbitrary memory addresses in the debuggee via PTRACE_PEEKDATA / PTRACE_POKEDATA
DWARF/ELF-aware breakpoints — on a breakpoint hit, resolves the current program counter to a function and source line using libelfin, then prints the surrounding source with the current line marked
PIE support — detects position-independent executables and computes the runtime load address from /proc/<pid>/maps so DWARF offsets resolve correctly
Interactive REPL — command-line interface built on linenoise, with command history


Commands

CommandDescriptionbreak 0xADDRESSSet a breakpoint at the given addresscontContinue execution until the next breakpoint or exitregister dumpPrint all register valuesregister read <reg>Print the value of a single registerregister write <reg> 0xVALUESet a register to a valuememory read 0xADDRESSRead a 64-bit value from memorymemory write 0xADDRESS 0xVALUEWrite a 64-bit value to memory

Commands accept unambiguous prefixes (e.g. c for cont, reg for register).

Project structure

.
├── CMakeLists.txt
├── include/
│   ├── debugger.hpp       # debugger class: process/register/memory/DWARF interface
│   ├── breakpoint.hpp     # software breakpoint (int3 patch/restore)
│   └── registers.hpp      # x86-64 register table + get/set helpers
├── src/
│   └── minidbg.cpp        # REPL, command handling, DWARF line/function lookup
├── examples/              # sample debuggee programs used for manual testing
│   ├── hello.cpp
│   ├── variable.cpp
│   └── stack_unwinding.cpp
└── ext/                   # vendored dependencies (git submodules)
    ├── libelfin/          # ELF/DWARF parsing
    └── linenoise/         # line editing for the REPL

Building

Prerequisites


CMake ≥ 3.0
A C++14-capable compiler (g++/clang++)
make
Python (required by libelfin's build)


Clone and build

bashgit clone --recurse-submodules https://github.com/kielped4765/linux_advanced_debugger.git
cd linux_advanced_debugger
mkdir build && cd build
cmake ..
make

If you already cloned without --recurse-submodules, pull the dependencies in with:

bashgit submodule update --init --recursive

This builds:


minidbg — the debugger itself
hello, variable, unwinding — small example debuggees (compiled with debug info) for exercising the debugger


Usage

Compile a target with debug symbols, then hand it to minidbg:

bashg++ -g -O0 examples/variable.cpp -o variable
./build/minidbg ./variable

minidbg> break 0x<address-of-interest>
Set breakpoint at address 0x...
minidbg> cont
Hit breakpoint at address 0x...
> int a = 42;
minidbg> register read rax
0x...
minidbg> register dump
...
