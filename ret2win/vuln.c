#include <stdio.h>

/* gcc -fno-stack-protector -no-pie ./vuln.c -o vuln */

char flag[] = "CS2107{test_flag}";

void win() {
	puts(flag);
    	fflush(stdout);
}

int main() {
	char buf[32];
	gets(buf);
	return 0;
}
