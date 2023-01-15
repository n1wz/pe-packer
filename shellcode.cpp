#include <string>
#include <vector>
#include "utils.h"
#include "shellcode.h"

enum {
	ADD, SUB, AND, OR, XOR, NOT
};

int shellcode::generate(int eax, char* out) {
	std::vector<std::pair<std::string, int>> instr {
		{ "\x05", ADD }, { "\x2D", SUB }, {"\x25", AND}, {"\x0D", OR}, {"\x35", XOR}, {"\xF7\xD0", NOT}
	};

	int total_instr = utils::rand(10, 15), out_s = 2;
	unsigned int eax_v = 0;

	for (int i = 0; i < total_instr; i++) {
		int cur_instr = utils::rand(0, instr.size() - 1), num = 0;

		switch (instr[cur_instr].second) {
			case ADD: {
				num = utils::rand(0, UINT_MAX - eax_v);
				eax_v += num;
				break;
			}
			case SUB: {
				num = utils::rand(0, eax_v);
				eax_v -= num;
				break;
			}
			case AND: {
				num = utils::rand(0, UINT_MAX);
				eax_v &= num;
				break;
			}
			case OR: {
				num = utils::rand(0, UINT_MAX);
				eax_v |= num;
				break;
			}
			case XOR: {
				num = utils::rand(0, UINT_MAX);
				eax_v ^= num;
				break;
			}
			case NOT: {
				eax_v = ~eax_v;
				break;
			}
		}

		memcpy(out + out_s, instr[cur_instr].first.c_str(), instr[cur_instr].first.size());
		if (instr[cur_instr].second != NOT) {
			memcpy(out + out_s + 1, &num, 4);
			out_s += 4;
		}
		out_s += instr[cur_instr].first.size();
	}

	if (eax_v > eax) {
		unsigned int n = eax_v - eax;
		memcpy(out + out_s, "\x2D", 1);
		memcpy(out + out_s + 1, &n, 4);
		out_s += 5;
	}
	else if (eax_v < eax) {
		unsigned int n = eax - eax_v;
		memcpy(out + out_s, "\x05", 1);
		memcpy(out + out_s + 1, &n, 4);
		out_s += 5;
	}

	memcpy(out, "\x31\xC0", 2); // xor eax, eax
	memcpy(out + out_s, "\xFF\xE0\xC3", 3); // jmp eax \n ret
	out_s += 3;

	return out_s;
}