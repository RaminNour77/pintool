/*
 * Copyright (C) 2004-2021 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

#include <iostream>
#include <fstream>
#include <execinfo.h>
#include <elfio/elfio.hpp>
#include <elfio/elfio_dump.hpp>

#include "pin.H"

using namespace std;
using namespace ELFIO;

// whitelist (since there is only one valid way to write to the GOT)
const std::string WHITELISTED = "_dl_rtld_di_serinfo";

// output file
ofstream OutFile;
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "part2.out", "specify output file name");

// functions
uint64_t lAddr, hAddr;
std::vector<std::pair<Elf64_Addr, std::string>> getSectionByName(elfio &reader, std::string section_name)
{
  std::vector<std::pair<Elf64_Addr, std::string>> sectionPairs;
  Elf_Half sec_num = reader.sections.size();
  for (int i = 0; i < sec_num; ++i)
  {
    section *psec = reader.sections[i];
    const relocation_section_accessor symbols(reader, psec);
    if (psec->get_name() == section_name)
    {
      for (unsigned int j = 0; j < symbols.get_entries_num(); ++j)
      {
        Elf64_Addr offset;
        Elf64_Addr symbolValue;
        std::string symbolName;
        Elf_Word type;
        Elf_Sxword addend;
        Elf_Sxword calcValue;
        symbols.get_entry(j, offset, symbolValue, symbolName, type, addend, calcValue);
        sectionPairs.push_back(std::make_pair(offset, symbolName));
      }
    }
  }
  return sectionPairs;
}

bool findGotRange(char *elfname, UINT64 &lAddr, UINT64 &hAddr)
{
  elfio reader;
  if (!reader.load(elfname))
  {
    OutFile << "Can't find or process ELF file " << elfname << std::endl;
    return false;
  }
  std::string section_name = ".rela.plt";
  auto sectionPairs = getSectionByName(reader, section_name);
  auto pairWithMinAddr = std::min_element(sectionPairs.begin(), sectionPairs.end(), [](const auto &a, const auto &b)
                                          { return a.first < b.first; });
  auto pairWithMaxAddr = std::max_element(sectionPairs.begin(), sectionPairs.end(), [](const auto &a, const auto &b)
                                          { return a.first < b.first; });
  lAddr = pairWithMinAddr->first;
  hAddr = pairWithMaxAddr->first;
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
    cout << "Bad intruder!!! no free arbitrary writes :P" << endl;
    OutFile << "Bad intruder!!! (unauthorized write) detected at: " << VoidStar2Addrint(write_ea) << endl;
    PIN_ExitProcess(2);
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

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
  OutFile << "This tool counts the number of dynamic instructions executed" << endl;
  OutFile << endl
          << KNOB_BASE::StringKnobSummary() << endl;
  return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */
/*   argc, argv are the entire command line: pin -t <toolname> -- ...    */
/* ===================================================================== */

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

  // Register trace instrumentation.
  TRACE_AddInstrumentFunction(Trace, 0);

  // Register Fini to be called when the application exits
  PIN_AddFiniFunction(Fini, 0);

  // Start the program, never returns
  PIN_StartProgram();

  return 0;
}
