#pragma once

namespace arguments {
	int argc;
	char** argv;

	void init(int l_argc, char** l_argv) {
		argc = l_argc;
		argv = l_argv;
	}
	
	bool has(const char* flag) {
		for (int i = 0; i < argc; i++) {
			if (strcmp(argv[i], flag) == 0)
				return true;
		}
		return false;
	}

	const char* get(const char* flag) {
		for (int i = 0; i < argc; i++) {
			if (strcmp(argv[i], flag) == 0)
				return argv[i + 1];
		}
		return 0;
	}
}