#include <stdio.h>
#include <syscall.h>

int
main (void) {
	
	char buf;
	read (STDIN_FILENO, &buf, 5);
	
	return 0;
}

