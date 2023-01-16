#include <iostream>
#include <fstream>
#include <vector>
#include "arguments.h"
#include "utils.h"
#include "shellcode.h"

HANDLE console;

int SECTION_SIZE = 0x400;
int KEY_SIZE = 0x100;

int main(int argc, char* argv[]) {
	console = GetStdHandle(STD_OUTPUT_HANDLE);
	arguments::init(argc, argv);

	if (argc < 3) {
		utils::log(console, "Using: pinkie-pie.exe [in] [out] [-key] [-obf]", 2);
		printf("-key [size]   Key size\n");
		printf("-obf          Enable WinAPI calls obuscation (test)\n");
		exit(1);
	}

	utils::log(console, "pe-packer v0.4", 3);

	std::ifstream file(argv[1], std::ios::binary | std::ios::ate);
	if (!file) {
		utils::log(console, "Failed to open file", 2);
		exit(2);
	}

	// Checking arguments
	const char* arg_key = arguments::get("-key");
	if (arg_key != 0) {
		KEY_SIZE = atoi(arg_key);
		SECTION_SIZE += KEY_SIZE;
	}
	bool arg_obf = arguments::has("-obf");

	// Allocating buffer & reading file
	int file_size = file.tellg();
	char* buffer = new char[file_size + SECTION_SIZE + 0x10000];
	file.seekg(0, std::ios::beg);
	file.read(buffer, file_size);
	file.close();

	// Getting dos & nt headers
	PIMAGE_DOS_HEADER dos = reinterpret_cast<PIMAGE_DOS_HEADER>(buffer);
	PIMAGE_NT_HEADERS nt = reinterpret_cast<PIMAGE_NT_HEADERS>(buffer + dos->e_lfanew);

	// Checking file support
	if (nt->Signature != IMAGE_NT_SIGNATURE) {
		utils::log(console, "Invalid PE file", 2);
		exit(3);
	}
	if (nt->FileHeader.Machine != 332) {
		utils::log(console, "Only x32 files are supported", 2);
		exit(4);
	}
	if (nt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) {
		utils::log(console, "Dynamic base is not supported", 2);
		exit(4);
	}

	utils::log(console, "Parsing sections . . .", 1);

	// Getting data directories
	PIMAGE_DATA_DIRECTORY imports = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	PIMAGE_DATA_DIRECTORY iat = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
	PIMAGE_DATA_DIRECTORY debug = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
	int imports_offset = utils::rva2offset(imports->VirtualAddress, nt);

	// Removing debug directory
	if (debug->Size != 0) {
		int debug_offset = utils::rva2offset(debug->VirtualAddress, nt);
		ZeroMemory(buffer + debug_offset, debug->Size);
		ZeroMemory(debug, 8);
		utils::log(console, "Debug directory removed", 0);
	}

	int c_code_sec = 0;
	PIMAGE_SECTION_HEADER* code_sec = (PIMAGE_SECTION_HEADER*)malloc(nt->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));

	// Parsing sections
	PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
	for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
		if (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE && sec->Characteristics & IMAGE_SCN_CNT_CODE) {
			code_sec[c_code_sec] = sec;
			c_code_sec++;
		}
		sec++;
	}

	if (c_code_sec == 0)
		utils::log(console, "No code sections found", 4);

	char* winapi_calls = new char[0x10000], *shell_buffer = new char[0x1000];
	static int winapi_calls_s = 0;

	// Parsing PE file import table
	if (arg_obf) {
		utils::log(console, "Obfuscating WinAPI calls . . .", 1);

		PIMAGE_IMPORT_DESCRIPTOR descriptor = (PIMAGE_IMPORT_DESCRIPTOR)(buffer + imports_offset);
		for (; descriptor->FirstThunk; descriptor++) {
			// Loading module
			HMODULE cur_module = LoadLibraryA((char*)(buffer + utils::rva2offset(descriptor->Name, nt)));
			if (!cur_module)
				continue;

			// Parsing import functions
			int va_next_sec = utils::correct_num((sec - 1)->VirtualAddress + (sec - 1)->Misc.VirtualSize, nt->OptionalHeader.SectionAlignment);
			PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)(buffer + utils::rva2offset(descriptor->FirstThunk, nt));
			for (int t = 0; thunk->u1.AddressOfData; t++) {
				PIMAGE_IMPORT_BY_NAME data = (PIMAGE_IMPORT_BY_NAME)(buffer + utils::rva2offset(thunk->u1.AddressOfData, nt));
				FARPROC func_addr = GetProcAddress(cur_module, data->Name);
				if (func_addr == NULL)
					continue;

				// Generating shellcode
				int size = shellcode::generate((int)func_addr, shell_buffer);
				memcpy(winapi_calls + winapi_calls_s, shell_buffer, size);
				winapi_calls_s += size;

				// Generating call signature
				*(int*)(shellcode::x86::import_call + 2) = nt->OptionalHeader.ImageBase + descriptor->FirstThunk + (t * 4);

				// Finding calls
				for (int i = 0; i < c_code_sec; i++) {
					int pos = utils::find_bytes((char*)shellcode::x86::import_call, 6, buffer, code_sec[i]->SizeOfRawData, code_sec[i]->PointerToRawData);
					while (pos != -1) {
						int rva = va_next_sec + winapi_calls_s - size - utils::offset2rva(pos, nt) - 5;
						*(char*)(buffer + pos) = '\xE8';
						*(int*)(buffer + pos + 1) = int(rva);
						*(char*)(buffer + pos + 5) = '\x90';

						pos = utils::find_bytes((char*)shellcode::x86::import_call, 6, buffer, code_sec[i]->SizeOfRawData, code_sec[i]->PointerToRawData + pos + 1);
					}
				}

				thunk++;
			}
		}
		SECTION_SIZE += winapi_calls_s;
	}

	utils::log(console, "Xoring section(s) . . .", 1);

	char* key = utils::generate_key(KEY_SIZE);
	for (int i = 0; i < c_code_sec; i++)
		utils::xor_crypt(buffer, code_sec[i]->PointerToRawData, code_sec[i]->SizeOfRawData, key, KEY_SIZE);
	if (arg_obf)
		utils::xor_crypt(winapi_calls, 0, winapi_calls_s, key, KEY_SIZE);

	utils::log(console, "Creating section . . .", 1);

	sec = (PIMAGE_SECTION_HEADER)utils::create_section(".kucd", file_size, SECTION_SIZE, IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE, nt);

	// Allocating memory for new section
	char* new_sec = new char[SECTION_SIZE];
	ZeroMemory(new_sec, SECTION_SIZE);
	int new_sec_s = winapi_calls_s;

	// Copying xor key to end of section
	memcpy(new_sec + SECTION_SIZE - KEY_SIZE, key, KEY_SIZE);

	*(int*)(shellcode::x86::crypt_init + 10) = KEY_SIZE;
	memcpy(new_sec + new_sec_s, shellcode::x86::crypt_init, sizeof(shellcode::x86::crypt_init));

	for (int i = 0; i < c_code_sec; i++) {
		code_sec[i]->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE;

		// Generating shellcode for dexor section
		*(int*)(shellcode::x86::crypt + 11) = int(sec->VirtualAddress + SECTION_SIZE - KEY_SIZE);
		*(int*)(shellcode::x86::crypt + 18) = int(code_sec[i]->VirtualAddress);
		*(int*)(shellcode::x86::crypt + 25) = int(code_sec[i]->Misc.VirtualSize);
		memcpy(new_sec + new_sec_s + sizeof(shellcode::x86::crypt_init) + (i * sizeof(shellcode::x86::crypt)), shellcode::x86::crypt, sizeof(shellcode::x86::crypt));
	}
	new_sec_s += sizeof(shellcode::x86::crypt_init) + (c_code_sec * sizeof(shellcode::x86::crypt));

	if (arg_obf) {
		*(int*)(shellcode::x86::crypt + 11) = int(sec->VirtualAddress + SECTION_SIZE - KEY_SIZE);
		*(int*)(shellcode::x86::crypt + 18) = int(sec->VirtualAddress);
		*(int*)(shellcode::x86::crypt + 25) = int(winapi_calls_s);
		memcpy(new_sec + new_sec_s, shellcode::x86::crypt, sizeof(shellcode::x86::crypt));
		new_sec_s += sizeof(shellcode::x86::crypt);
	}

	*(int*)(shellcode::x86::crypt_end + 2) = int(nt->OptionalHeader.AddressOfEntryPoint);
	memcpy(new_sec + new_sec_s, shellcode::x86::crypt_end, sizeof(shellcode::x86::crypt_end));
	new_sec_s += sizeof(shellcode::x86::crypt_end);

	memcpy(new_sec, winapi_calls, winapi_calls_s);

	// Changing entrypoint & copying new section
	nt->OptionalHeader.AddressOfEntryPoint = sec->VirtualAddress + winapi_calls_s;
	memmove(buffer + file_size, new_sec, SECTION_SIZE);

	std::ofstream out(argv[2], std::ios::binary);
	if (!out) {
		utils::log(console, "Failed to open file", 2);
		exit(6);
	}

	out.write(buffer, file_size + SECTION_SIZE);
	out.close();

	utils::log(console, "Success", 0);
	return 0;
}