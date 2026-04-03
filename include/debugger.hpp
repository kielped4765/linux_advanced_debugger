#ifndef MINIDBG_DEBUGGER_HPP
#define MINIDBG_DEBUGGER_HPP

#include <string>
#include <linux/types.h>
#include <unordered_map>
#include <iomanip>
#include <fcntl.h>
#include <signal.h>

#include "dwarf/dwarf++.hh"
#include "elf/elf++.hh"

#include "breakpoint.hpp"
#include "registers.hpp"

namespace minidbg {

class debugger {
public:
    debugger (std::string prog_name, pid_t pid)
        : m_prog_name{std::move(prog_name)}, m_pid{pid} {
            // Open the binary and load ELF/DWEARF data from it
        auto fd = open(m_prog_name.c_str(), 0_RDONLY);
        m_elf = elf::elf{elf::create_mmap_loader(fd)};
        m_dwarf = dwarf::dwarf{dwarf::elf::create_loader(m_elf)};
    }

    void run();

private:
    void handle_command(const std::string& line);
    void continue_execution();
    void set_breakpoint_at_address(std::intptr_t addr);
    void dump_registers();
    void step_over_breakpoint();
    void wait_for_signal();
    void initialise_load_address();
    void print_source(const std::string& file_name, unsigned line, unsigned n_lines_context = 2);
    void print_source(const std::string& file_name, unsigned line, unsigned n_lines_context = 2);
    void handle_sigtrap(siginfo_t info);

    // Memory 
    uint64_t read_memory(uint64_t address);
    void write_memory(uint64_t address, uint64_t value);

    // Program counter helpers
    uint64_t get_pc();
    void set_pc(uint64_t pc);

    // DWARF lookups
    dwarf::die get_function_from_pc(uint64_t pc);
    dwarf::line_table::iterator get_line_entry_from_pc(uint64_t pc);
    uint64_t offset_load_address(uint64_t addr);
    siginfo_t get_signal_info();

    std::string m_prog_name;
    pid_t m_pid;
    uint64_t m_load_address = 0;
    dwarf::dwarf m_dwarf;
    elf::elf m_elf;
    std::unordered_map<std::intptr_t, breakpoint> m_breakpoints;
};

} // namespace minidbg

#endif
