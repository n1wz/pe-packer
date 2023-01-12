#include <string>
#include <vector>
#include "utils.h"
#include "shellcode.h"

enum {
	ADD, SUB/*, AND, OR, XOR*/
};

int shellcode::generate(int eax, unsigned char* out) {
	std::vector<std::pair<std::string, int>> instr {
		{ "\x05", ADD }, { "\x2D", SUB }/*, {"\x25", AND}, {"\x0D", OR}, {"\x35", XOR},*/
	};
	int total_instr = utils::rand(5, 15), size = total_instr * 5 + 5, out_s = 0;
	unsigned int eax_v = INT_MAX;

	for (int i = 0; i < total_instr; i++) {
		int cur_instr = utils::rand(0, instr.size() - 1), num = 0;

		switch (instr[cur_instr].second) {
			case ADD: {
				num = utils::rand(0, INT_MAX - eax_v);
				eax_v += num;
				break;
			}
			case SUB: {
				num = utils::rand(0, eax_v);
				eax_v -= num;
				break;
			}
			/*case AND: {
				eax_v &= num;
				break;
			}
			case OR: {
				eax_v |= num;
				break;
			}
			case XOR: {
				eax_v ^= num;
				break;
			}*/
		}

		memcpy(out + size - out_s - 5, instr[cur_instr].first.c_str(), instr[cur_instr].first.size());
		memcpy(out + size - out_s - 4, &num, 4);
		out_s += instr[cur_instr].first.size() + 4;
	}

	int n = eax_v - eax;
	memcpy(out, "\xB8\xFF\xFF\xFF\x7F", 5); // mov eax, 0x7fffffff
	memcpy(out + out_s, "\x2D", 1);
	memcpy(out + 1, &n, 4);
	out_s += 5;

	return out_s;
}