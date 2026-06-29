#include <iostream>
#include <fstream>
#include "pin.H"
using std::cerr;
using std::endl;
using std::ios;
using std::ofstream;
using std::string;

ofstream OutFile;

// The running count of instructions and memory writes is kept here
// make them static to help the compiler optimize docount and memWriteCount
static UINT64 icount = 0;
static UINT64 memWriteCount = 0;

// This function is called before every block
// Use the fast linkage for calls
VOID PIN_FAST_ANALYSIS_CALL docount(ADDRINT c) { icount += c; }

// This function is called before every memory write instruction
VOID PIN_FAST_ANALYSIS_CALL domemwrite() { memWriteCount++; }

// Pin calls this function every time a new basic block is encountered
// It inserts a call to docount
VOID Trace(TRACE trace, VOID* v)
{
    // Visit every basic block in the trace
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        // Insert a call to docount for every bbl, passing the number of instructions.
        // IPOINT_ANYWHERE allows Pin to schedule the call anywhere in the bbl to obtain best performance.
        // Use a fast linkage for the call.
        BBL_InsertCall(bbl, IPOINT_ANYWHERE, AFUNPTR(docount), IARG_FAST_ANALYSIS_CALL, IARG_UINT32, BBL_NumIns(bbl), IARG_END);
    }

    // Visit every instruction in the trace
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
        {
            // Check if the instruction is a memory write
            if (INS_IsMemoryWrite(ins))
            {
                // Insert a call to domemwrite before every memory write instruction
                INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(domemwrite), IARG_FAST_ANALYSIS_CALL, IARG_END);
            }
        }
    }
}

KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "part0.out", "specify output file name");

// This function is called when the application exits
VOID Fini(INT32 code, VOID* v)
{
    // Write to a file since cout and cerr maybe closed by the application
    OutFile.setf(ios::showbase);
    OutFile << "Instruction Count: " << icount << endl;
    OutFile << "Memory Write Count: " << memWriteCount << endl;
    OutFile.close();
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    cerr << "This tool counts the number of dynamic instructions and memory writes executed" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char* argv[])
{
    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();

    OutFile.open(KnobOutputFile.Value().c_str());

    // Register Trace to be called to instrument instructions
    TRACE_AddInstrumentFunction(Trace, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}
