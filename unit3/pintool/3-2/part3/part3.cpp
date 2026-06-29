#include <iostream>
#include <fstream>
#include <execinfo.h>
#include <elfio/elfio.hpp>
#include <elfio/elfio_dump.hpp>

#include "pin.H"

using namespace std;
using namespace ELFIO;

ofstream OutFile;
uint64_t lAddr, hAddr;

// whitelist all functions that contain _dl_ at the begining
const std::string WHITELISTED = "_dl_rtld_di_serinfo";

// Adjusts lAddr and hAddr based on IMG object
bool findGotRangeUsingImg(IMG img)
{
    RTN pltRtn = RTN_FindByName(img, ".rela.plt");
    if (!RTN_Valid(pltRtn))
    {
        OutFile << "Failed to find .plt section." << endl;
        return false;
    }

    lAddr = RTN_Address(pltRtn);
    hAddr = lAddr + RTN_Size(pltRtn);
    OutFile << "GOT Range (using IMG): " << hex << lAddr << " ~~ " << hAddr << endl;
    return true;
}

VOID detectGotOverwrite(void *write_ea, const CONTEXT *ctxt)
{
    auto isInGot = (void *)lAddr <= write_ea && write_ea <= (void *)hAddr;
    if (!isInGot)
    {
        return;
    }
    void *buff[128];
    PIN_LockClient();
    PIN_Backtrace(ctxt, buff, sizeof(buff) / sizeof(buff[0]));
    PIN_UnlockClient();
    auto isAuthWrite = false;
    for (size_t i = 0; i < (size_t)sizeof(buff) / sizeof(buff[0]); ++i)
    {
        auto addrint = VoidStar2Addrint(buff[i]);
        auto function_name = RTN_FindNameByAddress(addrint);
        if (function_name == WHITELISTED)
        {
            isAuthWrite = true;
        }
    }
    if (!isAuthWrite)
    {
        OutFile << "Unauthorized write detected at: " << VoidStar2Addrint(write_ea) << endl;
        PIN_ExitProcess(2);
    }
}

VOID ImageLoad(IMG img, VOID *v)
{
    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {
        if (SEC_Name(sec) == ".rela.plt")
        {
            lAddr = SEC_Address(sec);
            hAddr = lAddr + SEC_Size(sec);
            OutFile << "Found .got.plt section from " << std::hex << lAddr << " to " << hAddr << std::endl;
        }
    }
    {
        if (!findGotRangeUsingImg(img))
        {
            OutFile << "Could not find GOT range for main executable" << std::endl;
            PIN_ExitProcess(1);
        }
    }
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
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)detectGotOverwrite, IARG_MEMORYWRITE_EA, IARG_CONST_CONTEXT, IARG_END);
            }
        }
    }
}

VOID Fini(INT32 code, VOID *v)
{
    OutFile << "Fini: " << hex << lAddr << " ~~ " << hAddr << endl;
    OutFile.close();
}

int main(int argc, char *argv[])
{
    if (PIN_Init(argc, argv))
    {
        OutFile << "Failed to initialize PIN" << endl;
        return -1;
    }

    OutFile.open("output.log");

    PIN_InitSymbols();

    IMG_AddInstrumentFunction(ImageLoad, 0);
    TRACE_AddInstrumentFunction(Trace, 0);
    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram();
    return 0;
}
