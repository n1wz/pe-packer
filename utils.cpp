#include <string>
#include <random>
#include "utils.h"

void utils::log(HANDLE console, const char* text, int t) {
	SetConsoleTextAttribute(console, t + 10);
	printf(t == 0 ? "[+]" : (t == 2 ? "[-]" : "[!]"));
	SetConsoleTextAttribute(console, 7);
	printf(" %s\n", text);
}

bool utils::in_range(int num, int min, int max) {
	return num >= min && num <= max;
}

int utils::rand(int min, int max) {
	std::random_device rd;
	std::mt19937 mt(rd());
	std::uniform_int<int> dist(min, max);
	return dist(mt);
}

char* utils::generate_key(int len) {
	char* out = new char[len];
	for (int i = 0; i < len; ++i)
		out[i] = rand(0x00, 0xFF);
	return out;
}

void utils::xor_crypt(char* p, int o, int s, char* key, int ks) {
	for (int i = 0; i < s; i++) {
		p[o + i] ^= key[i % ks];
	}
}

int utils::correct_num(int num, int to) {
	return num <= to ? to : num + to - (num % to);
}

void* utils::create_section(const char* name, int raw_addr, int size, int c, void* p) {
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)p;
	PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt) + nt->FileHeader.NumberOfSections;

	nt->FileHeader.NumberOfSections++;
	nt->OptionalHeader.SizeOfImage += correct_num(size, nt->OptionalHeader.SectionAlignment);
	ZeroMemory(sec, sizeof(IMAGE_SECTION_HEADER));
	memcpy(sec->Name, name, strlen(name));
	sec->Misc.VirtualSize = correct_num(size, nt->OptionalHeader.SectionAlignment);
	sec->SizeOfRawData = size;
	sec->Misc.PhysicalAddress = size;
	sec->VirtualAddress = correct_num((sec - 1)->VirtualAddress + (sec - 1)->Misc.VirtualSize, nt->OptionalHeader.SectionAlignment);
	sec->PointerToRawData = raw_addr;
	sec->Characteristics = c;

	return sec;
}

int utils::rva2offset(int rva, void* p) {
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)p;
	PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

	if (rva < sec[0].PointerToRawData)
		return rva;

	for (int index = 0; index < nt->FileHeader.NumberOfSections; index++) {
		if (rva >= sec[index].VirtualAddress && rva < (sec[index].VirtualAddress + sec[index].SizeOfRawData))
			return (rva - sec[index].VirtualAddress + sec[index].PointerToRawData);
	}

	return 0;
}

int utils::offset2rva(int offset, void* p) {
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)p;
	PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

	if (offset < sec[0].PointerToRawData)
		return offset;

	for (int index = 0; index < nt->FileHeader.NumberOfSections; index++) {
		if (offset >= sec[index].PointerToRawData && offset < (sec[index].PointerToRawData + sec[index].SizeOfRawData))
			return (offset - sec[index].PointerToRawData + sec[index].VirtualAddress);
	}

	return 0;
}

int utils::find_bytes(char* bytes, int bs, char* p, int s, int off) {
	std::string b(bytes, bs), m(p, s);
	return m.find(b, off);
}