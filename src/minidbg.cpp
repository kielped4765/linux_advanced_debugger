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
#include <string.h>
#include <algorithm>

#include "linenoise.h"
#include "debugger.hpp"
#include "registers.hpp"

namespace minidbg {

    class ptrace_expr_context : public dwarf::expr_context {
    public:
        ptrace_expr_context (pid_t pid) : m_pid{pid} {}

        dwarf::taddr reg (unsigned regnum) override {
            return get_register_value_from_dwarf_register(m_pid, regnum);
        }

        dwarf::taddr pc() override {
            struct user_regs_struct regs; 
            ptrace(PTRACE_GETREGS, m_pid, nullptr, &regs);
            return regs.rip;
        }

        dwarf::taddr deref_size (dwarf::taddr address, unsigned size) override {
            return ptrace(PTRACE_PEEKDATA, m_pid, address, nullptr);
        }
    private:
        pid_t m_pid;
    }; // <--- Ensure this semicolon is here!

    void debugger::read_variables() {
        auto func = get_function_from_pc(offset_load_address(get_pc()));

        for (const auto& die : func) {
            if (die.tag == dwarf::DW_TAG::variable || die.tag == dwarf::DW_TAG::formal_parameter) {
                auto loc_val = die[dwarf::DW_AT::location];

                if (loc_val.get_type() == dwarf::value::type::exprloc) {
                    ptrace_expr_context context {m_pid};
                    auto result = loc_val.as_exprloc().evaluate(&context);

                    switch (result.location_type) {
                        case dwarf::expr_result::type::address: {
                            auto value = read_memory(result.value);
                            std::cout << dwarf::at_name(die) << " (0x" << std::hex << result.value << ") = " << value << std::dec << std::endl;
                            break;
                        }
                        case dwarf::expr_result::type::reg: {
                            auto value = get_register_value_from_dwarf_register(m_pid, result.value);
                            std::cout << dwarf::at_name(die) << " (reg " << result.value << ") = " << value << std::dec << std::endl;
                            break;
                        }
                        default:
                            throw std::runtime_error{"Unhandled variable location"};
                    }
                }
            }
        }
    }
} // end namespace minidbg

using namespace minidbg;

/**
 * --- HELPER FUNCTIONS ---
 */

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

uint64_t safe_stoll(const std::string& str) {
    if (str.empty()) return 0;
    try {
        size_t pos = (str.find("0x") == 0) ? 2 : 0;
        return std::stoull(str.substr(pos), nullptr, 16);
    } catch (...) {
        return 0;
    }
}

/**
 * --- DEBUGGER IMPLEMENTATION ---
 */

void debugger::initialise_load_address() {
    if (m_elf.get_hdr().type == elf::et::dyn) {
        std::ifstream map("/proc/" + std::to_string(m_pid) + "/maps");
        std::string addr;
        if (std::getline(map, addr, '-') && !addr.empty()) {
            m_load_address = safe_stoll(addr);
        }
    }
}

uint64_t debugger::offset_load_address(uint64_t addr) {
    return addr - m_load_address;
}

// Helper function to search DIEs recursively
dwarf::die search_dwarf_recursive(const dwarf::die& die, uint64_t pc) {
    if (die.tag == dwarf::DW_TAG::subprogram && die.has(dwarf::DW_AT::low_pc)) {
        if (dwarf::die_pc_range(die).contains(pc)) {
            return die;
        }
    }
    // Search children
    for (auto child : die) {
        try {
            return search_dwarf_recursive(child, pc);
        } catch (const std::out_of_range&) {
            continue; 
        }
    }
    throw std::out_of_range{"Cannot find function"};
}

dwarf::die debugger::get_function_from_pc(uint64_t pc) {
    for (auto &cu : m_dwarf.compilation_units()) {
        if (dwarf::die_pc_range(cu.root()).contains(pc)) {
            // The libdwarf++ iterator walks the entire tree depth-first
            for (auto die : cu.root()) {
                if (die.tag == dwarf::DW_TAG::subprogram && die.has(dwarf::DW_AT::low_pc)) {
                    if (dwarf::die_pc_range(die).contains(pc)) {
                        return die;
                    }
                }
            }
        }
    }
    throw std::out_of_range{"Cannot find function"};
}

dwarf::line_table::iterator debugger::get_line_entry_from_pc(uint64_t pc) {
    for (auto &cu : m_dwarf.compilation_units()) {
        if (dwarf::die_pc_range(cu.root()).contains(pc)) {
            auto &lt = cu.get_line_table();
            auto it = lt.find_address(pc);
            if (it == lt.end()) throw std::out_of_range{"Cannot find line entry"};
            return it;
        }
    }
    throw std::out_of_range{"Cannot find line entry"};
}

void debugger::print_source(const std::string& file_name, unsigned line, unsigned n_lines_context) {
    std::ifstream file {file_name};
    if (!file) return;

    auto start_line = line <= n_lines_context ? 1 : line - n_lines_context;
    auto end_line = line + n_lines_context + 1;

    char c{};
    auto current_line = 1u;
    while (current_line != start_line && file.get(c)) {
        if (c == '\n') ++current_line;
    }

    std::cout << (current_line == line ? "> " : "  ");
    while (current_line <= end_line && file.get(c)) {
        std::cout << c;
        if (c == '\n') {
            ++current_line;
            if (current_line <= end_line)
                std::cout << (current_line == line ? "> " : "  ");
        }
    }
    std::cout << std::endl;
}

void debugger::print_backtrace() {
    auto output_frame = [frame_number = 0, this] (auto&& func, uint64_t pc) mutable {
        std::cout << "frame #" << frame_number++ << ": 0x" 
                  << std::hex << pc << " "
                  << dwarf::at_name(func) << std::dec << std::endl;
    };

    uint64_t current_pc = get_pc();
    auto current_func = get_function_from_pc(offset_load_address(current_pc));
    output_frame(current_func, current_pc);

    auto frame_pointer = get_register_value(m_pid, reg::rbp);

    while (dwarf::at_name(current_func) != "main") {
        auto return_address = read_memory(frame_pointer + 8);
        
        // Subtract 1 to stay inside the calling function
        current_func = get_function_from_pc(offset_load_address(return_address - 1));
        output_frame(current_func, return_address);

        frame_pointer = read_memory(frame_pointer);
        if (frame_pointer == 0) break;
    }
}

/**
 * --- BREAKPOINT LOGIC ---
 */

void debugger::set_breakpoint_at_function(const std::string& name) {
    for (const auto& cu : m_dwarf.compilation_units()) {
        for (const auto& die : cu.root()) {
            if (die.has(dwarf::DW_AT::name) && dwarf::at_name(die) == name) {
                auto low_pc = dwarf::at_low_pc(die);
                auto entry = get_line_entry_from_pc(low_pc);
                ++entry; 
                set_breakpoint_at_address(offset_load_address(entry->address) + m_load_address);
            }
        }
    }
}

void debugger::set_breakpoint_at_source_line(const std::string& file, unsigned line) {
    for (auto &cu : m_dwarf.compilation_units()) {
        if (cu.root().has(dwarf::DW_AT::name) && dwarf::at_name(cu.root()).find(file) != std::string::npos) {
            auto &lt = cu.get_line_table();
            for (auto &entry : lt) {
                if (entry.is_stmt && entry.line == line) {
                    set_breakpoint_at_address(offset_load_address(entry.address) + m_load_address);
                    return;
                }
            }
        }
    }
}

void debugger::set_breakpoint_at_address(std::intptr_t addr) {
    std::cout << "Set breakpoint at address 0x" << std::hex << addr << std::dec << std::endl;
    breakpoint bp {m_pid, addr};
    bp.enable();
    m_breakpoints[addr] = bp;
}

/**
 * --- EXECUTION CONTROL ---
 */

void debugger::handle_sigtrap(siginfo_t info) {
    switch (info.si_code) {
    case SI_KERNEL:
    case TRAP_BRKPT:
    {
        set_pc(get_pc() - 1);
        std::cout << "Hit breakpoint at address 0x" << std::hex << get_pc() << std::dec << std::endl;
        try {
            auto offset_pc = offset_load_address(get_pc());
            auto line_entry = get_line_entry_from_pc(offset_pc);
            print_source(line_entry->file->path, line_entry->line);
        } catch (...) {
            std::cout << "No source info available." << std::endl;
        }
        return;
    }
    case TRAP_TRACE: return;
    default: return;
    }
}

siginfo_t debugger::get_signal_info() {
    siginfo_t info;
    ptrace(PTRACE_GETSIGINFO, m_pid, nullptr, &info);
    return info;
}

void debugger::wait_for_signal() {
    int wait_status;
    waitpid(m_pid, &wait_status, 0);

    if (WIFEXITED(wait_status)) {
        std::cout << "Process exited." << std::endl;
        exit(0);
    }

    siginfo_t siginfo = get_signal_info();
    if (siginfo.si_signo == SIGTRAP) {
        handle_sigtrap(siginfo);
    }
}

void debugger::single_step_instruction() {
    ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
    wait_for_signal();
}

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

void debugger::step_in() {
    try {
        auto line = get_line_entry_from_pc(offset_load_address(get_pc()))->line;
        while (get_line_entry_from_pc(offset_load_address(get_pc()))->line == line) {
            if (m_breakpoints.count(get_pc())) {
                step_over_breakpoint();
            } else {
                single_step_instruction();
            }
        }
        auto line_entry = get_line_entry_from_pc(offset_load_address(get_pc()));
        print_source(line_entry->file->path, line_entry->line);
    } catch (...) {
        single_step_instruction();
    }
}

void debugger::step_out() {
    auto frame_pointer = get_register_value(m_pid, reg::rbp);
    auto return_address = read_memory(frame_pointer + 8);

    bool should_remove_breakpoint = false;
    if (!m_breakpoints.count(return_address)) {
        set_breakpoint_at_address(return_address);
        should_remove_breakpoint = true;
    }

    continue_execution();

    if (should_remove_breakpoint) {
        m_breakpoints.erase(return_address);
    }
}

void debugger::continue_execution() {
    step_over_breakpoint();
    ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);
    wait_for_signal();
}

/**
 * --- COMMAND HANDLER ---
 */

void debugger::handle_command(const std::string& line) {
    auto args = split(line, ' ');
    if (args.empty()) return;
    auto command = args[0];

    if (is_prefix(command, "continue")) {
        continue_execution();
    }
    else if (is_prefix(command, "break")) {
    auto arg = args[1];
    if (is_prefix(arg, "0x")) {
        set_breakpoint_at_address(safe_stoll(arg));
    } else {
        bool found = false;
        for (auto &cu : m_dwarf.compilation_units()) {
            for (const auto& die : cu.root()) {
                // 1. Check if it's a function (subprogram)
                // 2. Check if it actually HAS a name attribute before calling at_name
                if (die.tag == dwarf::DW_TAG::subprogram && 
                    die.has(dwarf::DW_AT::name) && 
                    dwarf::at_name(die) == arg) {
                    
                    auto addr = dwarf::at_low_pc(die) + m_load_address;
                    set_breakpoint_at_address(addr);
                    std::cout << "Set breakpoint at function " << arg 
                              << " (address 0x" << std::hex << addr << ")" << std::endl;
                    found = true;
                    break;
                }
            }
            if (found) break; 
        }
        if (!found) std::cerr << "Could not find function " << arg << std::endl;
    }
}
    else if (is_prefix(command, "step")) {
        step_in();
    }
    else if (is_prefix(command, "finish")) {
        step_out();
    }
    else if (is_prefix(command, "register")) {
        if (args.size() > 1 && is_prefix(args[1], "dump")) dump_registers();
    }
    else if (is_prefix(command, "backtrace")) {
        print_backtrace();
    }
    else if (is_prefix(command, "variables")) {
        read_variables();
    }
    else {
        std::cerr << "Unknown command\n";
    }
}

/**
 * --- CORE FUNCTIONS ---
 */

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

void debugger::dump_registers() {
    for (const auto& rd : g_register_descriptors) {
        std::cout << std::left << std::setw(8) << rd.name << " 0x"
                  << std::setfill('0') << std::setw(16) << std::hex
                  << get_register_value(m_pid, rd.r) << std::dec << std::endl;
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
        std::cerr << "Program name not specified\n";
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