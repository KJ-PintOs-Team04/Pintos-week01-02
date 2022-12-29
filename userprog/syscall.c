#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/init.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "userprog/process.h"
#include "threads/flags.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/input.h"
#include "lib/stdio.h"
#include "lib/kernel/stdio.h"
#include "intrinsic.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
void halt (void);
void exit (int status);
bool create (const char *file, unsigned initial_size);
int open (const char *file);
void close (int fd);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void check_address(void *addr);
/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	// printf ("system call!\n");
	// thread_exit ();
	switch (f->R.rax)
	{
		case SYS_HALT:
			halt();
			break;
		case SYS_EXIT:
			exit(f->R.rdi);
			break;
		// case SYS_FORK:
		// 	break;
		// case SYS_EXEC:
		//  f->R.rax = exec(f->R.rdi);
		// 	break;
		// case SYS_WAIT:
		// 	break;
		case SYS_CREATE:
			check_address(f->R.rdi);
			f->R.rax = create(f->R.rdi, f->R.rsi);
			break;
		// case SYS_REMOVE:
		// 	check_address(f->R.rdi);
		// 	f->R.rax = remove(f->R.rdi);
		// 	break;
		case SYS_OPEN:
			check_address(f->R.rdi);
			f->R.rax = open(f->R.rdi);
			break;
		case SYS_FILESIZE:
			f->R.rax = filesize(f->R.rdi);
			break;
		case SYS_READ:
			check_address(f->R.rsi);
			f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE:
			check_address(f->R.rsi);
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		// case SYS_SEEK:
		// 	// seek(f->R.rdi, f->R.rsi);
		// 	break;
		// case SYS_TELL:
		// 	// f->R.rax = tell(f->R.rdi);
		// 	break;
		case SYS_CLOSE:
			close(f->R.rdi);
			break;
		default:
			exit (-1);
	}
}

void halt(void) {
	power_off();
}

void exit (int status) {
	struct thread *curr = thread_current();
	curr->exit_status = status; //  정상적으로 종료 시 status는 0
	printf("%s: exit(%d)\n", curr->name, status);
	thread_exit();
	// TODO: close all files, Deallocate the file descriptor table.
}

bool create(const char *file, unsigned initial_size) {
	return filesys_create(file, initial_size);
}

/* 파일을 열 때 사용하는 시스템 콜 */
int open(const char *file) {
	struct file *fileptr;
	// root_dir 부터 file(파일 이름)찾아 포인터 반환
	fileptr = filesys_open(file);
	
	// 실패 시 -1 반환
	if (fileptr == NULL)
		return -1;
	// 성공 시 fdt에 fileptr 저장 후 fd 반환
	return process_add_file(fileptr);
}

/* 열린 파일을 닫는 시스템 콜 */
void close (int fd) {
	struct file *fileptr;

	fileptr = process_get_file(fd);
	if (fileptr) {
		file_close(fileptr);
		process_close_file(fd);
	}
}

int filesize(int fd) {

	struct thread *curr;
	struct file *fileptr;
	off_t length;

	curr = thread_current();
	fileptr = curr->fdt[fd];

	// 성공 시 파일의 크기를 반환, 실패 시 -1 반환
	length = file_length(fileptr);
	if (length > 0)
		return length;
	else
		return -1;
}

/* fd로 열린 파일에서 buffer에(메모리) 저장 */
int read(int fd, void *buffer, unsigned size) {
	off_t byte;
	struct file *fileptr;

	if (fd == STDOUT_FILENO)
		return -1;

	// reads from keyboard
	if (fd == STDIN_FILENO)
		return input_getc();

	fileptr = process_get_file(fd);

	if (fileptr) {
		// Reads SIZE bytes from FILE into BUFFER
		// 읽은 데이터가 있으면 byte 반환
		byte = file_read(fileptr, buffer, size);
		return byte;
	}
	return -1;
}

/* 열린 파일(fd)에 버퍼를 write */
int write(int fd, const void *buffer, unsigned size) {
	off_t byte;
	struct file *fileptr;

	if (fd == STDIN_FILENO)
		return -1;

	if (fd == STDOUT_FILENO) {
		putbuf(buffer, size);
		return size;
	}
	
	if (fileptr = process_get_file(fd)) {
		byte = file_write(fileptr, buffer, size);
		return byte;
	}
	return -1;
}

/* 주소 값이 유저 영역에서 사용하는 주소 값인지 확인하는 함수 */
void check_address(void *addr) {
	struct thread *t = thread_current();

	if (addr == NULL || pml4_get_page (t->pml4, addr) == NULL || !is_user_vaddr (addr))
		exit(-1);
}
