#include <iostream>
#include <fstream>
#include <set>
#include <pin.H>

#include <execinfo.h>
#include <elfio/elfio.hpp>
#include <elfio/elfio_dump.hpp>

using namespace std;
using namespace ELFIO;

// whitelist (since there is only one valid way to write to the GOT)
const std::string WHITELISTED = "_dl_rtld_di_serinfo";

// output file
ofstream OutFile;
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "part3.out", "specify output file name");

uint64_t lAddr = 0, hAddr = 0;  // Range for GOT entries
set<ADDRINT> protectedOffsets;   // Set of addresses to protect (GOT and specific functions)

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
    cout << "Bad intruder!!! no free arbitrary writes :P"<< endl;
    OutFile << "Bad intruder!!! (unauthorized write) detected at: " << VoidStar2Addrint(write_ea) << endl;
    PIN_ExitProcess(2);
  }
}

// Attempts to locate the GOT section range in the given IMG
bool findGotRangeUsingImg(IMG img) {
    SEC sec;
    bool found = false;

    // Check each section to find .got or .got.plt
    for (sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
        if (SEC_Name(sec) == ".got" || SEC_Name(sec) == ".got.plt") {
            lAddr = SEC_Address(sec);
            hAddr = lAddr + SEC_Size(sec);
            OutFile << "Found GOT Section (" << SEC_Name(sec) << "): " << hex << lAddr << " - " << hAddr << endl;

            // Add GOT addresses to protected set
            for (ADDRINT addr = lAddr; addr < hAddr; addr += sizeof(void*)) {
                protectedOffsets.insert(addr);
            }
            found = true;
        }
    }
    return found;
}

// Locate specific function addresses through symbols and add to protection set
void findFunctionOffsetsUsingSymbols(IMG img) {
    for (SYM sym = IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym)) {
        string symName = PIN_UndecorateSymbolName(SYM_Name(sym), UNDECORATION_COMPLETE);
        // check if symName has _dl_ at the beginning
        if (symName.find("_dl_") == 0) {  
            ADDRINT funcAddr = IMG_LowAddress(img) + SYM_Value(sym);
            OutFile << "Protecting function " << symName << " at address: " << hex << funcAddr << endl;
            protectedOffsets.insert(funcAddr);
        }
    }
}

// Function to check for unauthorized writes
VOID detectUnauthorizedWrite(void *write_ea, const CONTEXT *ctxt) {
    if (protectedOffsets.find((ADDRINT)write_ea) != protectedOffsets.end()) {
        OutFile << "Unauthorized write attempt detected at protected address: " << hex << (ADDRINT)write_ea << endl;
        PIN_ExitProcess(2);
    }
}

// Instrument each image for GOT and function offset protections
VOID ImageLoad(IMG img, VOID *v) {
    bool foundGot = findGotRangeUsingImg(img);
    if (!foundGot) {
        OutFile << "No GOT sections found in image: " << IMG_Name(img) << ", scanning symbols instead." << endl;
        findFunctionOffsetsUsingSymbols(img);
    }
}

// Trace writes to detect unauthorized attempts
VOID Trace(TRACE trace, VOID *v) {
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
            if (INS_IsMemoryWrite(ins)) {
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)detectUnauthorizedWrite,
                               IARG_MEMORYWRITE_EA, IARG_CONST_CONTEXT, IARG_END);
            }
        }
    }
}

// Clean up and close output file on program completion
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
  OutFile << "This tool prevents got overwrites" << endl;
  OutFile << endl
          << KNOB_BASE::StringKnobSummary() << endl;
  return -1;
}

int main(int argc, char *argv[]) 
{
    if (PIN_Init(argc, argv)) 
        return Usage();
    

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
   

    // Initialize symbol processing early
    PIN_InitSymbols();

    OutFile.open(KnobOutputFile.Value().c_str());
    if (!OutFile.is_open()) {
        cerr << "Error: Could not open output file." << endl;
        return 1;
    }

    IMG_AddInstrumentFunction(ImageLoad, 0);
    TRACE_AddInstrumentFunction(Trace, 0);
    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram();
    return 0;
}