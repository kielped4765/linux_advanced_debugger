#include <vector>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/personality.h>
#include <unistd.h>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <signal.h>

#include "linenoise.h"
#include "debugger.hpp"
#include "registers.hpp"

using namespace minidbg;

std::vector<std::string> split(const std::string &s, char delimiter) {
    std::vector<std::string> out{};
    std::stringstream ss {s};
    std::string item;
    while (std::getline(ss, item, delimiter)) {
        out.push_back(item);
    }
    return out;
}

bool is_prefix(const std::string& s, const std::string& of) {
    if (s.size() > of.size()) return false;
    return std::equal(s.begin(), s.end(), of.begin());
}

// *** NEW *** - reads the ELF/DWARF type for a DIE's pc range
// This is a helper used by get_function_from_pc and get_line_entry_from_pc
dwarf::taddr die_pc_range(const dwarf::die& d) {
    // Try DW_AT_high_pc first
    if (d.has(dwarf::DW_AT::high_pc)) {
        return d[dwarf::DW_AT::high_pc].as_address();
    }
    // Some compilers use a size instead of an end address
    if (d.has(dwarf::DW_AT::ranges)) {
        auto ranges = dwarf::die_pc_range(d);
        return ranges.end()->high;
    }
    throw std::out_of_range{"DIE has no PC range"};
}

// *** NEW *** - automatically find the load address from /proc/<pid>/maps
void debugger::initialise_load_address() {
    // Only needed for position-independent executables (PIE)
    if (m_elf.get_hdr().type == elf::et::dyn) {
        std::ifstream map("/proc/" + std::to_string(m_pid) + "/maps");
        std::string addr;
        std::getline(map, addr, '-');
        m_load_address = std::stoi(addr, 0, 16);
    }
}

// *** NEW *** - subtract the load address so DWARF offsets match
uint64_t debugger::offset_load_address(uint64_t addr) {
    return addr - m_load_address;
}

// *** NEW *** - find which function a program counter value is inside
dwarf::die debugger::get_function_from_pc(uint64_t pc) {
    for (auto &cu : m_dwarf.compilation_units()) {
        if (dwarf::die_pc_range(cu.root()).contains(pc)) {
            for (const auto& die : cu.root()) {
                if (die.tag == dwarf::DW_TAG::subprogram) {
                    if (dwarf::die_pc_range(die).contains(pc)) {
                        return die;
                    }
                }
            }
        }
    }
    throw std::out_of_range{"Cannot find function"};
}

// *** NEW *** - find which source line a program counter value maps to
dwarf::line_table::iterator debugger::get_line_entry_from_pc(uint64_t pc) {
    for (auto &cu : m_dwarf.compilation_units()) {
        if (dwarf::die_pc_range(cu.root()).contains(pc)) {
            auto &lt = cu.get_line_table();
            auto it = lt.find_address(pc);
            if (it == lt.end()) {
                throw std::out_of_range{"Cannot find line entry"};
            }
            else {
                return it;
            }
        }
    }
    throw std::out_of_range{"Cannot find line entry"};
}

// *** NEW *** - print source code around the current line
void debugger::print_source(const std::string& file_name, unsigned line, unsigned n_lines_context) {
    std::ifstream file {file_name};

    auto start_line = line <= n_lines_context ? 1 : line - n_lines_context;
    auto end_line = line + n_lines_context +
                    (line < n_lines_context ? n_lines_context - line : 0) + 1;

    char c{};
    auto current_line = 1u;

    // Skip lines before the window we want to show
    while (current_line != start_line && file.get(c)) {
        if (c == '\n') ++current_line;
    }

    std::cout << (current_line == line ? "> " : "  ");

    // Print lines in the window, marking the current line with >
    while (current_line <= end_line && file.get(c)) {
        std::cout << c;
        if (c == '\n') {
            ++current_line;
            std::cout << (current_line == line ? "> " : "  ");
        }
    }
    std::cout << std::endl;
}

// *** NEW *** - ask ptrace what signal was sent and why
siginfo_t debugger::get_signal_info() {
    siginfo_t info;
    ptrace(PTRACE_GETSIGINFO, m_pid, nullptr, &info);
    return info;
}

// *** NEW *** - handle SIGTRAP specifically (breakpoints and single steps)
void debugger::handle_sigtrap(siginfo_t info) {
    switch (info.si_code) {
    case SI_KERNEL:
    case TRAP_BRKPT:
    {
        set_pc(get_pc() - 1); // rewind rip back before the 0xCC byte
        std::cout << "Hit breakpoint at address 0x" << std::hex << get_pc() << std::endl;
        auto offset_pc = offset_load_address(get_pc());
        auto line_entry = get_line_entry_from_pc(offset_pc);
        print_source(line_entry->file->path, line_entry->line);
        return;
    }
    case TRAP_TRACE: // sent after a single step completes
        return;
    default:
        std::cout << "Unknown SIGTRAP code " << info.si_code << std::endl;
        return;
    }
}

// *** UPDATED *** - now understands WHY it was stopped
void debugger::wait_for_signal() {
    int wait_status;
    auto options = 0;
    waitpid(m_pid, &wait_status, options);

    auto siginfo = get_signal_info();

    switch (siginfo.si_signo) {
    case SIGTRAP:
        handle_sigtrap(siginfo);
        break;
    case SIGSEGV:
        std::cout << "Yay, segfault. Reason: " << siginfo.si_code << std::endl;
        break;
    default:
        std::cout << "Got signal " << strsignal(siginfo.si_signo) << std::endl;
    }
}

// *** UPDATED *** - pc correction now happens in handle_sigtrap, not here
void debugger::step_over_breakpoint() {
    if (m_breakpoints.count(get_pc())) {
        auto& bp = m_breakpoints[get_pc()];
        if (bp.is_enabled()) {
            bp.disable();
            ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
            wait_for_signal();
            bp.enable();
        }
    }
}

// *** UPDATED *** - now calls initialise_load_address on startup
void debugger::run() {
    wait_for_signal();
    initialise_load_address();

    char* line = nullptr;
    while ((line = linenoise("minidbg> ")) != nullptr) {
        handle_command(line);
        linenoiseHistoryAdd(line);
        linenoiseFree(line);
    }
}

void debugger::handle_command(const std::string& line) {
    auto args = split(line, ' ');
    auto command = args[0];

    if (is_prefix(command, "cont")) {
        continue_execution();
    }
    else if (is_prefix(command, "break")) {
        std::string addr {args[1], 2};
        set_breakpoint_at_address(std::stol(addr, 0, 16));
    }
    else if (is_prefix(command, "register")) {
        if (is_prefix(args[1], "dump")) {
            dump_registers();
        }
        else if (is_prefix(args[1], "read")) {
            std::cout << get_register_value(m_pid, get_register_from_name(args[2])) << std::endl;
        }
        else if (is_prefix(args[1], "write")) {
            std::string val {args[3], 2};
            set_register_value(m_pid, get_register_from_name(args[2]), std::stol(val, 0, 16));
        }
    }
    else if (is_prefix(command, "memory")) {
        std::string addr {args[2], 2};
        if (is_prefix(args[1], "read")) {
            std::cout << std::hex << read_memory(std::stol(addr, 0, 16)) << std::endl;
        }
        if (is_prefix(args[1], "write")) {
            std::string val {args[3], 2};
            write_memory(std::stol(addr, 0, 16), std::stol(val, 0, 16));
        }
    }
    else {
        std::cerr << "Unknown command\n";
    }
}

void debugger::continue_execution() {
    step_over_breakpoint();
    ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);
    wait_for_signal();
}

void debugger::set_breakpoint_at_address(std::intptr_t addr) {
    std::cout << "Set breakpoint at address 0x" << std::hex << addr << std::endl;
    breakpoint bp {m_pid, addr};
    bp.enable();
    m_breakpoints[addr] = bp;
}

void debugger::dump_registers() {
    for (const auto& rd : g_register_descriptors) {
        std::cout << rd.name << " 0x"
                  << std::setfill('0') << std::setw(16) << std::hex
                  << get_register_value(m_pid, rd.r) << std::endl;
    }
}

uint64_t debugger::read_memory(uint64_t address) {
    return ptrace(PTRACE_PEEKDATA, m_pid, address, nullptr);
}

void debugger::write_memory(uint64_t address, uint64_t value) {
    ptrace(PTRACE_POKEDATA, m_pid, address, value);
}

uint64_t debugger::get_pc() {
    return get_register_value(m_pid, reg::rip);
}

void debugger::set_pc(uint64_t pc) {
    set_register_value(m_pid, reg::rip, pc);
}

void execute_debugee(const std::string& prog_name) {
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
        std::cerr << "Error in ptrace\n";
        return;
    }
    execl(prog_name.c_str(), prog_name.c_str(), nullptr);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Program name not specified";
        return -1;
    }

    auto prog = argv[1];
    auto pid = fork();

    if (pid == 0) {
        personality(ADDR_NO_RANDOMIZE);
        execute_debugee(prog);
    }
    else if (pid >= 1) {
        std::cout << "Started debugging process " << pid << '\n';
        debugger dbg{prog, pid};
        dbg.run();
    }
}