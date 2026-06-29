#include <iostream>
#include <fstream>
#include <pin.H>
#include <elfio/elfio.hpp>

using namespace std;
using namespace ELFIO;

ADDRINT got_start = 0;
ADDRINT got_end = 0;
string allowed_function = "_dl_rtld_di_serinfo";

// Function to parse ELF and find GOT section
void FindGOT(const string &elf_file) {
    elfio reader;
    if (!reader.load(elf_file)) {
        cerr << "Could not load ELF file: " << elf_file << endl;
        exit(1);
    }

    for (int i = 0; i < reader.sections.size(); ++i) {
        section *psec = reader.sections[i];
        if (psec->get_name() == ".got") {
            got_start = psec->get_address();
            got_end = got_start + psec->get_size();
            break;
        }
    }

    if (got_start == 0 || got_end == 0) {
        cerr << "GOT section not found in ELF file: " << elf_file << endl;
        exit(1);
    }
}

// Function to check if the address is within GOT range
bool IsInGOTRange(ADDRINT addr) {
    return addr >= got_start && addr < got_end;
}

// Function to trace back the call stack
bool IsCalledFromAllowedFunction(CONTEXT *ctxt) {
    ADDRINT ip = PIN_GetContextReg(ctxt, REG_INST_PTR);
    RTN rtn = RTN_FindByAddress(ip);
    if (RTN_Valid(rtn)) {
        string func_name = RTN_Name(rtn);
        return func_name == allowed_function;
    }
    return false;
}

// Function to handle memory writes
VOID RecordMemWrite(ADDRINT addr, CONTEXT *ctxt) {
    if (IsInGOTRange(addr)) {
        if (!IsCalledFromAllowedFunction(ctxt)) {
            cerr << "Suspicious write to GOT detected at address: 0x" << hex << addr << endl;
            PIN_ExitProcess(1);
        }
    }
}

// Instruction instrumentation function
VOID Instruction(INS ins, VOID *v) {
    if (INS_IsMemoryWrite(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite, IARG_MEMORYWRITE_EA, IARG_CONTEXT, IARG_END);
    }
}

// Main function
int main(int argc, char *argv[]) {
    if (PIN_Init(argc, argv)) {
        cerr << "This Pintool detects suspicious writes to GOT" << endl;
        return 1;
    }

    if (argc < 2) {
        cerr << "Usage: " << argv[0] << " <ELF file>" << endl;
        return 1;
    }

    FindGOT(argv[1]);

    INS_AddInstrumentFunction(Instruction, 0);

    PIN_StartProgram();
    return 0;
}