#include <iostream>
#include <fstream>
#include <pin.H>
#include <unordered_set>

using namespace std;

// Define the whitelist function names for authorized writes
const std::string WHITELISTED = "_dl_rtld_di_serinfo";
ofstream OutFile;
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "part3.out", "Output file name");

// Global variables for tracking the `.rela.plt` section
ADDRINT lAddr, hAddr;
bool section_initialized = false;

// Function to initialize address range for `.rela.plt` within the executable image
bool InitRelocSection(IMG img) {
    bool got_found = false;
    bool got_plt_found = false;

    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
        if (SEC_Name(sec) == ".got") {
            lAddr = SEC_Address(sec);
            got_found = true;
        } else if (SEC_Name(sec) == ".got.plt") {
            hAddr = SEC_Address(sec) + SEC_Size(sec);
            got_plt_found = true;
        }

        if (got_found && got_plt_found) {
            section_initialized = true;
            return true;
        }
    }
    return false;
}

// Check if an address is within the GOT/PLT range
bool IsInRelocSection(ADDRINT addr) {
    return section_initialized && addr >= lAddr && addr < hAddr;
}

// Function to check write attempts against the whitelist and unauthorized access
VOID DetectWrite(ADDRINT writeAddr, CONTEXT* ctxt) {
    if (IsInRelocSection(writeAddr)) {
        void* backtrace[128];
        PIN_LockClient();
        PIN_Backtrace(ctxt, backtrace, sizeof(backtrace) / sizeof(backtrace[0]));
        PIN_UnlockClient();
        // Flag to track authorized functions
        bool isAuthorized = false;

        for (size_t i = 0; i < sizeof(backtrace) / sizeof(backtrace[0]); ++i) {
            auto funcAddr = reinterpret_cast<ADDRINT>(backtrace[i]);
            std::string funcName = RTN_FindNameByAddress(funcAddr);

            if (funcName == WHITELISTED) {
                isAuthorized = true;
                break;
            }
        }

        if (!isAuthorized) {
            cout << "Unauthorized write attempt detected at address: " << hex << writeAddr << endl;
            OutFile << "Unauthorized write attempt detected at address: " << hex << writeAddr << endl;
            PIN_ExitProcess(2);
        }
    }
}

// Routine for detecting memory writes and invoking `DetectWrite`
VOID Trace(TRACE trace, VOID* v) {
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
            if (INS_IsMemoryWrite(ins)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)DetectWrite, IARG_MEMORYWRITE_EA, IARG_CONST_CONTEXT, IARG_END);
            }
        }
    }
}

VOID Fini(INT32 code, VOID *v)
{
  OutFile.setf(ios::showbase);
  OutFile << "Fini: ";
  OutFile << hex << lAddr << " " << hAddr << " " << endl;
  OutFile.close();
}

// Initialize Pin Tool
INT32 Usage() {
    cerr << "This tool prevents unauthorized writes to the .rela.plt section" << endl;
    return -1;
}

int main(int argc, char* argv[]) {
    if (PIN_Init(argc, argv)) return Usage();
    OutFile.open(KnobOutputFile.Value().c_str());

    char *cmd = NULL;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            cmd = argv[++i];
            break;
        }
    }

    if (!InitRelocSection(IMG_Open(cmd))) {
        OutFile << "Could not find GOT range" << std::endl;
        return -1;
    }

    // Initialize Symbols
    PIN_InitSymbols();

    // Load image
    IMG_AddInstrumentFunction([](IMG img, VOID* v) {
        if (InitRelocSection(img)) {
            cout << "Initialized .rela.plt section range: " << hex << lAddr << " - " << hAddr << endl;
            OutFile << "Initialized .rela.plt section range: " << hex << lAddr << " - " << hAddr << endl;
        }
    }, nullptr);

    // Register Trace function
    TRACE_AddInstrumentFunction(Trace, 0);

    //call fini when the program exits 
    PIN_AddFiniFunction(Fini, 0);
    
    // Start the program
    PIN_StartProgram();
    return 0;
}
