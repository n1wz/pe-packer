#include <Windows.h>
#include <iostream>
#include <fstream>
#include <random>
#include "shellcode.h"

HANDLE console;

#define SECTION_SIZE 0x400
#define KEY_SIZE 128

void log(const char* text, int t) {
	SetConsoleTextAttribute(console, t + 10);
	printf(t == 0 ? "[+]" : (t == 2 ? "[-]" : "[!]"));
	SetConsoleTextAttribute(console, 7);
	printf(" %s\n", text);
}

char* generate_key(int len) {
	char* out = new char[len];
	std::random_device rd;
	std::mt19937 mt(rd());
	std::uniform_int<int> dist(0x00, 0xFF);
	for (int i = 0; i < len; ++i)
		out[i] = dist(mt);
	return out;
}

void xor_crypt(char* p, int o, int s, char* key, int ks) {
	for (int i = 0; i < s; i++) {
		p[o + i] ^= key[i % ks];
	}
}

int main(int argc, char* argv[]) {
	console = GetStdHandle(STD_OUTPUT_HANDLE);

	if (argc != 3) {
		log("Using: pinkie-pie.exe [in] [out]", 2);
		exit(1);
	}

	log("pinkie-pie v0.1", 3);

	std::ifstream file(argv[1], std::ios::binary | std::ios::ate);
	if (!file) {
		log("Failed to open file", 2);
		exit(2);
	}

	int file_size = file.tellg();
	char* buffer = new char[file_size + SECTION_SIZE];
	file.seekg(0, std::ios::beg);
	file.read(buffer, file_size);
	file.close();

	PIMAGE_DOS_HEADER dos = reinterpret_cast<PIMAGE_DOS_HEADER>(buffer);
	PIMAGE_NT_HEADERS nt = reinterpret_cast<PIMAGE_NT_HEADERS>(buffer + dos->e_lfanew);

	if (nt->Signature != IMAGE_NT_SIGNATURE) {
		log("Invalid PE file", 2);
		exit(3);
	}

	if (nt->FileHeader.Machine != 332) {
		log("Only x32 files are supported", 2);	
		exit(4);
	}

	log("Parsing sections . . .", 1);
	PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt), text_sec = NULL, rdata_sec = NULL;
	for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
		//sec->Misc.VirtualSize = nt->OptionalHeader.SectionAlignment + sec->Misc.VirtualSize - (sec->Misc.VirtualSize % nt->OptionalHeader.SectionAlignment);
		//printf("%s\t%X\t%X\t%X\t%X\n", sec->Name, sec->Misc.VirtualSize, sec->VirtualAddress, sec->SizeOfRawData, sec->PointerToRawData);
		
		if (sec->Characteristics == 0x60000020) 
			text_sec = sec;
		else if 
			(strcmp((const char*)sec->Name, ".rdata")) rdata_sec = sec;
		sec++;
	}

	if (!text_sec) {
		log("No .text section found", 2);
		exit(5);
	}

	log("Xoring section(s) . . .", 1);

	char* key = generate_key(KEY_SIZE);
	xor_crypt(buffer, text_sec->PointerToRawData, text_sec->SizeOfRawData, key, KEY_SIZE);

	text_sec->Characteristics = 0xE0000020;

	log("Creating section . . .", 1);

	nt->FileHeader.NumberOfSections++;
	nt->OptionalHeader.SizeOfImage += SECTION_SIZE;
	ZeroMemory(sec, sizeof(IMAGE_SECTION_HEADER));
	memcpy(sec->Name, ".ku\x00", 4);
	sec->Misc.VirtualSize = SECTION_SIZE;
	sec->SizeOfRawData = SECTION_SIZE;
	sec->Misc.PhysicalAddress = SECTION_SIZE;
	sec->VirtualAddress = ((sec - 1)->VirtualAddress + nt->OptionalHeader.SectionAlignment + round((sec - 1)->Misc.VirtualSize / nt->OptionalHeader.SectionAlignment) * nt->OptionalHeader.SectionAlignment);
	sec->PointerToRawData = file_size;
	sec->Characteristics = 0xE0000000;

	char* new_sec = new char[SECTION_SIZE];
	ZeroMemory(new_sec, SECTION_SIZE);

	memcpy(new_sec + SECTION_SIZE - KEY_SIZE, key, KEY_SIZE);

	DWORD old = 0;
	VirtualProtect((LPVOID)shellcode::crypt, SECTION_SIZE, PAGE_EXECUTE_READWRITE, &old);

	*(int*)(shellcode::crypt + 10) = KEY_SIZE;
	*(int*)(shellcode::crypt + 26) = int(sec->VirtualAddress + SECTION_SIZE - KEY_SIZE);
	*(int*)(shellcode::crypt + 34) = int(text_sec->VirtualAddress);
	*(int*)(shellcode::crypt + 43) = int(text_sec->Misc.VirtualSize);
	*(int*)(shellcode::crypt + 52) = int(nt->OptionalHeader.AddressOfEntryPoint);
	memcpy(new_sec, shellcode::crypt, sizeof(shellcode::crypt));

	nt->OptionalHeader.AddressOfEntryPoint = sec->VirtualAddress;

	memmove(buffer + file_size, new_sec, SECTION_SIZE);

	std::ofstream out(argv[2], std::ios::binary);
	if (!out) {
		log("Failed to open file", 2);
		exit(6);
	}

	out.write(buffer, file_size + SECTION_SIZE);
	out.close();

	log("Success", 0);
	return 0;
}