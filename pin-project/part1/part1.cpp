#include <iostream>
#include <iomanip>
#include <elfio/elfio.hpp>

using namespace ELFIO;
using namespace std;

void print_got_range(const relocation_section_accessor& rels) {
    Elf64_Addr offset;
    Elf64_Addr symbol_value;
    std::string symbol_name;
    Elf_Word type;
    Elf_Sxword addend;
    Elf_Sxword calcValue;

    bool first_found = false;
    Elf64_Addr first_offset = 0;
    Elf64_Addr last_offset = 0;

    for (unsigned int j = 0; j < rels.get_entries_num(); ++j) {
        rels.get_entry(j, offset, symbol_value, symbol_name, type, addend, calcValue);

        if (type == 7) {
            if (!first_found) {
                first_offset = offset;
                first_found = true;
            }
            last_offset = offset;
        }
    }

    if (first_found) {
        cout << "GOT range: 0x" << hex << first_offset << " ~ 0x" << hex << last_offset << endl << endl;
    }
}

void print_relocations(const relocation_section_accessor& rels) {
    Elf64_Addr offset;
    Elf64_Addr symbol_value;
    std::string symbol_name;
    Elf_Word type;
    Elf_Sxword addend;
    Elf_Sxword calcValue;

    // Print table header
    cout << "Offset          Symbol name" << endl;
    cout << "---------------------------------" << endl;

    for (unsigned int j = 0; j < rels.get_entries_num(); ++j) {
        // Get relocation entry details
        rels.get_entry(j, offset, symbol_value, symbol_name, type, addend, calcValue);

        if (type == 6) {
            cout << hex << setw(16) << setfill('0') << offset << "    " << symbol_name << " (.rela.dyn)" << endl;
        } else if (type == 7) {
            cout << hex << setw(16) << setfill('0') << offset << "    " << symbol_name << " (.rela.plt)" << endl;
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        cerr << "Usage: " << argv[0] << " <ELF file>" << endl;
        return 1;
    }

    elfio reader;

    // Load the ELF file
    if (!reader.load(argv[1])) {
        cerr << "Could not load ELF file: " << argv[1] << endl;
        return 1;
    }

    bool got_range_printed = false;
    Elf_Half sec_num = reader.sections.size();
    for (int i = 0; i < sec_num; ++i){
        section* psec = reader.sections[i];
        if (psec->get_type() == SHT_REL || psec->get_type() == SHT_RELA) {
            const relocation_section_accessor rels(reader, psec);
            print_relocations(rels);
            print_got_range(rels);
        }
    }
}
