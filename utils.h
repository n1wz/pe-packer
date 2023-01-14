#pragma once
#include <Windows.h>

namespace utils {
	void log(HANDLE console, const char* text, int t);
	bool in_range(int num, int min, int max);
	int rand(int min, int max);
	char* generate_key(int len);
	void xor_crypt(char* p, int o, int s, char* key, int ks);
	int correct_num(int num, int to);
	void* create_section(const char* name, int raw_addr, int size, int c, void* p);
	int rva2offset(int rva, void* p);
	int offset2rva(int offset, void* p);
	int find_bytes(char* bytes, int bs, char* p, int s, int off = 0);
}