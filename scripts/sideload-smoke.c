/* Minimal Sliver-Sideload-shaped loader: dlopen + Run(args). */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef void (*run_fn)(char *args);

int main(int argc, char **argv) {
	if (argc < 2) {
		fprintf(stderr, "usage: %s <lib.dylib|.so> [args...]\n", argv[0]);
		return 2;
	}

	void *h = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
	if (!h) {
		fprintf(stderr, "dlopen: %s\n", dlerror());
		return 1;
	}

	run_fn run = (run_fn)dlsym(h, "Run");
	if (!run) {
		fprintf(stderr, "dlsym(Run): %s\n", dlerror());
		dlclose(h);
		return 1;
	}

	char *args = NULL;
	if (argc > 2) {
		/* Join remaining argv with spaces, like Sliver Sideload -a */
		size_t n = 0;
		for (int i = 2; i < argc; i++) {
			n += strlen(argv[i]) + 1;
		}
		args = malloc(n);
		if (!args) {
			return 1;
		}
		args[0] = '\0';
		for (int i = 2; i < argc; i++) {
			if (i > 2) {
				strcat(args, " ");
			}
			strcat(args, argv[i]);
		}
	}

	printf("sideload-smoke: calling Run(%s)\n", args ? args : "NULL");
	fflush(stdout);
	run(args);
	printf("sideload-smoke: Run returned\n");

	free(args);
	dlclose(h);
	return 0;
}
