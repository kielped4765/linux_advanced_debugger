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
        
        auto fd = open(m_prog_name.c_str(), O_RDONLY);
        m_elf = elf::elf(elf::create_mmap_loader(fd));
        m_dwarf = dwarf::dwarf(dwarf::elf::create_loader(m_elf));
    }

    // --- Execution Control ---
    void run();
    void continue_execution();
    void single_step_instruction();
    void step_in();
    void step_out();
    void step_over_breakpoint();

    // --- Breakpoint Logic ---
    void set_breakpoint_at_address(std::intptr_t addr);
    void set_breakpoint_at_function(const std::string& name);
    void set_breakpoint_at_source_line(const std::string& file, unsigned line);

    // --- Register & Memory Helpers ---
    void dump_registers();
    uint64_t read_memory(uint64_t address);
    void write_memory(uint64_t address, uint64_t value);
    uint64_t get_pc();
    void set_pc(uint64_t pc);

private:
    // --- Internal Logic ---
    void handle_command(const std::string& line);
    void wait_for_signal();
    void initialise_load_address();
    void print_source(const std::string& file_name, unsigned line, unsigned n_lines_context = 2);
    void handle_sigtrap(siginfo_t info);
    siginfo_t get_signal_info();

    // --- DWARF / ELF Helpers ---
    dwarf::die get_function_from_pc(uint64_t pc);
    dwarf::line_table::iterator get_line_entry_from_pc(uint64_t pc);
    uint64_t offset_load_address(uint64_t addr);

    // --- Member Variables ---
    std::string m_prog_name;
    pid_t m_pid;
    uint64_t m_load_address = 0;
    dwarf::dwarf m_dwarf;
    elf::elf m_elf;
    std::unordered_map<std::intptr_t, breakpoint> m_breakpoints;
};

} // namespace minidbg

#endif
