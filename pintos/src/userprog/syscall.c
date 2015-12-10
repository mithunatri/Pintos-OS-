#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "syscall.h"
#include "process.h"
#include "pagedir.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/interrupt.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

#define MAX_BUFFER_SIZE 256
#define SYS_ERROR -1

static void 	syscall_handler (struct intr_frame *);

static void 	sys_halt (void);
static void 	sys_exit (int);
static int 	sys_exec (const void *);
static int 	sys_wait (int);
static bool 	sys_create (const char *, unsigned);
static bool 	sys_remove (const char *);
static int  	sys_open (const char *);
static int  	sys_filesize (int);
static int  	sys_read (int, const char *, unsigned);
static int 	sys_write (int, const char *, unsigned);
static void 	sys_seek (int, int);
static int  	sys_tell (int);
static void 	sys_close (int);


static struct 	lock g_file_lock;


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&g_file_lock);
}

/**Validates if the ptr is valid in the user address space and whether
the address is mapped in the kernel. Invokes sys_exit with -1 status
code if both these conditions fail. Else, it returns the kernel virtual
address. **/
static const void*
address_chk (const void *ptr) {

	if ( ptr==NULL || !is_user_vaddr (ptr) || 
		pagedir_get_page (thread_current()->pagedir, ptr) == NULL ) {

		sys_exit (SYS_ERROR);
	}
	return pagedir_get_page (thread_current()->pagedir, ptr);
}


/**Verifies whether every page between buffer start and buffer end are
mapped. If not, invokes sys_exit with -1 status code. Else, returns the
start address of the buffer. **/
static bool 
buffer_chk (const char *buffer, unsigned size) {
 	
//         if (buffer == NULL) return false;
 	
	 const void *next_address=buffer; 
	/*If size of buffer is less than one full page, then check
          buffer+remaining size instead of buffer+PGSIZE. */
	  unsigned i=1;
	  while (i <= size) {
		
		if ( (size-i) < PGSIZE )  next_address = next_address + size;
	
		else 	next_address = next_address + PGSIZE;
		
 		/**If page unmapped, then error. **/	
		if (pagedir_get_page (thread_current ()->pagedir, next_address) == NULL) {
			return false;
		}
	
		i+=PGSIZE;
	}

	return true;
}

/*Check whether the filename is valid/invalid. We need to verify if each
character of the filename is mapped in memory. Additionaly, file names are
limited to 14 characters.*/
/*static bool
file_valid (const char *filename) {

	int i;
	for (i=0; i <= 14; i++) {
	
		filename++;
	
		if (filename == NULL) return false;
		else if (*filename == '\0') return true;
	}
	
	//If filesize is greater than max_file_size, invalid file.
	return false;
}*/

/**Function to check if FD is valid for the process. Return false
if invalid. **/
static bool
fd_valid (int fd) {

	if (fd > 128 || thread_current ()->fd_array[fd] == NULL ) return false;

	return true;
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  uint32_t *stack_ptr=(uint32_t *)f->esp;

  if (pagedir_get_page (thread_current ()->pagedir, stack_ptr) == NULL) {
	sys_exit (SYS_ERROR);
  }
 
  int syscall_number=*(int *)stack_ptr;
  //printf("\n\nSyscall Number: %d", (int) syscall_number); 
  
  uint32_t args[2];
  switch (syscall_number){

	case SYS_HALT:
	 	sys_halt();
		break;

	case SYS_EXIT:	
		args[0] = *(uint32_t *)address_chk (stack_ptr+1);
		sys_exit ((int) args[0]);
		break;

	case SYS_EXEC:
		args[0] = *(uint32_t *)address_chk (stack_ptr+1);
		f->eax = sys_exec ((const void*)args[0]);
		break;

	case SYS_WAIT:
		args[0] = *(uint32_t *)address_chk (stack_ptr+1);	
		f->eax = sys_wait ((int) args[0]);
		break;

	case SYS_CREATE:
		args[0] = *(uint32_t *)address_chk (stack_ptr+1);
		args[1] = *(uint32_t *)address_chk (stack_ptr+2);
		f->eax = (uint32_t) sys_create ((const char *) args[0], (unsigned) args[1]);
		break;

	case SYS_REMOVE:
		args[0] = *(uint32_t *)address_chk (stack_ptr+1);
		f->eax = (bool) sys_remove ((const char *) args[0]);
		break;

	case SYS_OPEN:
		args[0] = *(uint32_t *)address_chk (stack_ptr+1);
                f->eax = (int) sys_open ((const char *)args[0]);
		break;

	case SYS_FILESIZE:
		 args[0] = *(uint32_t *)address_chk (stack_ptr+1);		           
		 f->eax = (int) sys_filesize ((int) args[0]);
		 break;

	case SYS_READ:
		args[0] = *(uint32_t *)address_chk (stack_ptr+1);
		args[1] = *(uint32_t *)address_chk (stack_ptr+2);
                args[2] = *(uint32_t *)address_chk (stack_ptr+3);
                f->eax = (int) sys_read ((int) args[0], (const char *) args[1], (int)args[2]);
		break;

	case SYS_WRITE:
		args[0] = *(uint32_t *)address_chk (stack_ptr+1);
		args[1] = *(uint32_t *)address_chk (stack_ptr+2);
		args[2] = *(uint32_t *)address_chk (stack_ptr+3);
		f->eax = (int) sys_write ((int)args[0], (const char *) args[1], (int)args[2]);
		break;

	case SYS_SEEK:
		args[0] = *(uint32_t *)address_chk (stack_ptr+1);
		args[1] = *(uint32_t *)address_chk (stack_ptr+2);
		sys_seek ((int) args[0], (int) args[1]);
		break;

	case SYS_TELL:
		args[0] = *(uint32_t *)address_chk (stack_ptr+1);
		f->eax = (int) sys_tell ((int) args[0]);
		break;

	case SYS_CLOSE:	
		args[0] = *(uint32_t *)address_chk (stack_ptr+1);
		sys_close ((int) args[0]);
		break;

	default:	
		sys_exit (SYS_ERROR);
		break;
  }

  return f->eax;
}

/**Halt System Call **/
static void
sys_halt (void){

	shutdown_power_off ();

}

/**Exit System Call **/
static void
sys_exit (int status){
	struct thread *cur = thread_current ();
	cur->exit_status = status;
	/*Close all open files. Dereference file entry in fd_array.*/
	int index;
	for (index = 2; index < 128; index ++) {
	
		if (cur->fd_array[index] != NULL) {
			file_close (cur->fd_array[index]);
			cur->fd_array[index]=NULL;
		}
	}
	thread_exit ();
}

static int
sys_exec (const void *buffer){
	printf("\nExec");
	return 1;
}

static int
sys_wait (int pid){
	
	int exit_status = process_wait (pid);
	return exit_status;
}

static bool 
sys_create (const char *filename, unsigned size){
	
  	/*if (pagedir_get_page (thread_current ()->pagedir, filename) == NULL) {
		sys_exit (SYS_ERROR);
 	 }*/
	if(filename == NULL || !address_chk (filename) || !buffer_chk (filename, strlen (filename))) { 
		sys_exit (SYS_ERROR);
	}

	lock_acquire (&g_file_lock);
	
	bool success = filesys_create (filename, size);
  	
	lock_release (&g_file_lock);
	
	return success;
}

static bool 
sys_remove (const char *filename) {

	if(filename == NULL || !buffer_chk (filename, strlen (filename))) {
		sys_exit (SYS_ERROR);
	}

	lock_acquire (&g_file_lock);
	
	bool success = filesys_remove (filename);
  	
	lock_release (&g_file_lock);
	
	return success;
}

static int
sys_open (const char *filename) {

	if(filename == NULL || !address_chk (filename) || !buffer_chk (filename, strlen (filename))) {
		sys_exit (SYS_ERROR);
	}

	lock_acquire (&g_file_lock);

	struct file *file = filesys_open (filename);
	
	lock_release (&g_file_lock);
	
	if (file == NULL)	return -1;
	
	struct thread *current = thread_current ();

	/*assign fd to open file. FD starts from 2 as FD=0,1 is assigned to
	STDIN_FILENO and STDOUT_FILENO respectively.*/
	int 	index;
	int 	fd = 2;
	for (index = 2; index < 128; index++) {
		if (current->fd_array[index] == NULL) {
		
			current->fd_array[index]=file;
			fd = index;
			break;
		}
	}			
				
	return fd;	
}

static int 
sys_filesize (int fd) {
	
	if (!fd_valid (fd))	sys_exit (SYS_ERROR);

	lock_acquire (&g_file_lock);
	
	struct file *file = thread_current ()->fd_array[fd];
        if (file == NULL)	sys_exit (SYS_ERROR);
	int filesize = file_length (file);
	
	lock_release (&g_file_lock);

	return filesize;
}

static int
sys_read (int fd, const char *buffer, unsigned size){

	if(!address_chk (buffer) || !buffer_chk (buffer, size) || (fd != STDIN_FILENO && !fd_valid (fd))) {
		  sys_exit (SYS_ERROR);
	}

	int read_size = 0;

	if (fd == STDIN_FILENO) {
		unsigned i;
		for (i = 0; i < size; i++) {
			*(char *)buffer = input_getc();
			 buffer++;
		}
		read_size = size;
	}
	else {
		lock_acquire (&g_file_lock);
	
		struct file *file = thread_current ()->fd_array[fd];
		if (file == NULL)	sys_exit (SYS_ERROR);
		read_size = file_read (file, (char *)buffer, size);
	
		lock_release (&g_file_lock);
	}

	return read_size;
}

static int 
sys_write (int fd, const char *buffer, unsigned size) {

	if(!buffer_chk (buffer, size) || (fd != STDOUT_FILENO && !fd_valid (fd))) {
		sys_exit (SYS_ERROR);
	}

	int write_size = 0;
	if (fd == STDOUT_FILENO){

		write_size = size;
	
		/*Write in MAX block size of 256 bytes*/	
		while (size > MAX_BUFFER_SIZE) {
			
			putbuf (buffer, MAX_BUFFER_SIZE);
			buffer += MAX_BUFFER_SIZE;	//may cause some pointer arithmetic problem
			size -=MAX_BUFFER_SIZE;
		}
		putbuf (buffer, size);
	}
	else {
	
		lock_acquire (&g_file_lock);

		struct file *file = thread_current ()->fd_array[fd];
		if (file == NULL)	sys_exit (SYS_ERROR);
		write_size = file_write (file, buffer, size);
		
		lock_release (&g_file_lock);
	}		

//	printf("\nWrite");
	return write_size;
}

static void 
sys_seek (int fd, int position) {

	if (!fd_valid (fd))	sys_exit (SYS_ERROR);

	lock_acquire (&g_file_lock);

        struct file *file = thread_current ()->fd_array[fd];
        if (file == NULL)	sys_exit (SYS_ERROR);
        file_seek (file, position);

	lock_release (&g_file_lock); 

}

static int 
sys_tell (int fd) {

	if(!fd_valid (fd))	sys_exit (SYS_ERROR);

	lock_acquire (&g_file_lock);
	 
	struct file *file = thread_current ()->fd_array[fd];
        if (file == NULL)	sys_exit (SYS_ERROR);
	int offset = file_tell (file);
	
	lock_release (&g_file_lock);
	
	return offset;
}

static void
sys_close (int fd) {
	
	if(!fd_valid (fd))	sys_exit (SYS_ERROR);

	lock_acquire (&g_file_lock);
	
        struct file *file = thread_current ()->fd_array[fd];
        if (file == NULL)	sys_exit (SYS_ERROR);
	file_close (file);
	thread_current ()->fd_array[fd]=NULL;
	
	lock_release (&g_file_lock);
}
