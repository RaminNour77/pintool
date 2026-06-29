#include <iostream>
#include <fstream>
#include <execinfo.h>
#include <elfio/elfio.hpp>
#include <elfio/elfio_dump.hpp>

#include "pin.H"

using namespace std;
std::ofstream OutFile;

// Define the address range for .rela.plt section
ADDRINT pltStart = 0;
ADDRINT pltEnd = 0;

// Function to check if a function name allows writes to .rela.plt
bool IsWriteAllowedByFunctionName(std::string funcName)
{
    // Allow if function name contains "_dl_"
    return funcName.find("_dl_") != std::string::npos;
}

// Image load callback
VOID ImageLoad(IMG img, VOID *v)
{
    // Loop through sections to find .rela.plt
    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {
        if (SEC_Name(sec) == ".rela.plt")
        {
            pltStart = SEC_Address(sec);
            pltEnd = pltStart + SEC_Size(sec);
            OutFile << "Found .rela.plt section from " << std::hex << pltStart << " to " << pltEnd << std::endl;
        }
    }
}

// Memory write callback with function name filtering
VOID PreventWrite(ADDRINT addr, std::string funcName)
{
    // Check if address falls within .rela.plt section and if write is allowed
    if (addr >= pltStart && addr < pltEnd)
    {
        if (!IsWriteAllowedByFunctionName(funcName))
        {
            OutFile << "Attempted unauthorized write to .rela.plt at address " << std::hex << addr
                    << " by function: " << funcName << std::endl;
            PIN_ExitApplication(1);  // Exit if unauthorized write attempt detected
        }
    }
}

// Instruction callback for memory write detection, retrieves function name
VOID Instruction(INS ins, VOID *v)
{
    if (INS_IsMemoryWrite(ins))
    {
        RTN rtn = INS_Rtn(ins);
        std::string funcName = RTN_Valid(rtn) ? RTN_Name(rtn) : "";

        // Add a call to PreventWrite with the function name as a parameter
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)PreventWrite,
                                 IARG_MEMORYWRITE_EA, IARG_PTR, new std::string(funcName), IARG_END);
    }
}

// Pin tool initialization
INT32 Usage()
{
    std::cerr << "This tool prevents unauthorized writes to the .rela.plt section of an ELF file." << std::endl;
    return -1;
}

VOID Trace(TRACE trace, VOID *v)
{
  for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
  {
    for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
    {
      if (!INS_IsMemoryWrite(ins))
      {
        continue;
      }
      UINT32 memOperands = INS_MemoryOperandCount(ins);
      for (UINT32 memOp = 0; memOp < memOperands; memOp++)
      {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)PreventWrite, IARG_MEMORYWRITE_EA, IARG_CONST_CONTEXT, IARG_END);
      }
    }
  }
  return;
}

// This function is called when the application exits
VOID Fini(INT32 code, VOID *v)
{
  OutFile.setf(ios::showbase);
  OutFile << "Fini: ";
  OutFile << hex << lAddr << " " << hAddr << " " << endl;
  OutFile.close();
}

int main(int argc, char *argv[])
{
    if (PIN_Init(argc, argv))
    {
        return Usage();
    }

    OutFile.open("part3.out");
    PIN_InitSymbols();
    
    IMG_AddInstrumentFunction(ImageLoad, 0);
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram();
    return 0;
}



int main(int argc, char *argv[])
{
  // Initialize pin
  if (PIN_Init(argc, argv))
    return Usage();

  OutFile.open(KnobOutputFile.Value().c_str());

  char *cmd = NULL;
  for (int i = 0; i < argc; i++)
  {
    if (strcmp(argv[i], "--") == 0)
    {
      cmd = argv[++i];
      break;
    }
  }

  if (!findGotRange(cmd, lAddr, hAddr))
  {
    OutFile << "Could not find GOT range" << std::endl;
    return -1;
  }
  OutFile << "Range: " << lAddr << " ~~ " << hAddr << endl;
  // Initialize symbol processing
  PIN_InitSymbols();

  //instrument the image
  IMG_AddInstrumentFunction(ImageLoad, 0);

  // Register trace instrumentation.
  TRACE_AddInstrumentFunction(Trace, 0);

  // Register Fini to be called when the application exits
  PIN_AddFiniFunction(Fini, 0);

  // Start the program, never returns
  PIN_StartProgram();

  return 0;
}