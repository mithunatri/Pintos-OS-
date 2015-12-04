/* Open a file. */

#include <syscall.h>
#include <stdio.h>

int
main (void) 
{
  int handle = open ("sample.txt");
  
  printf("\nHandle: %d", handle);
	
  return 0;
}

