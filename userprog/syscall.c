#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "threads/init.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "intrinsic.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
void halt (void);
void exit (int status);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);

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
syscall_init (void) { // To do: initialize lock 
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
	// 유저 스택 포인터(esp) 주소와 시스템 콜 인자가 가리키는 주소(포인터)가 유효 주소 (유저 영역)인지 확인하도록 구현
	switch (f->R.rax)
	{

		case SYS_HALT:
			halt();
			break;
		case SYS_EXIT:
			exit(f->R.rdi);
			break;
		case SYS_FORK:
			break;
		case SYS_EXEC:
			break;
		case SYS_WAIT:
			break;
		case SYS_CREATE:
			f->R.rax = create(f->R.rdi, f->R.rsi);
			break;
		case SYS_REMOVE:
			f->R.rax = remove(f->R.rdi);
			break;
		case SYS_OPEN:
			f->R.rax = open(f->R.rdi);
			break;
		case SYS_FILESIZE:
			f->R.rax = filesize(f->R.rdi);
			break;
		case SYS_READ:
			break;
		case SYS_WRITE:
			break;
		case SYS_SEEK:
			break;
		case SYS_TELL:
			break;
		case SYS_CLOSE:
			break;
	}
}

void halt(void) {
	power_off();
}

void exit (int status) {
	struct thread *curr = thread_current();
	curr->exit_status = status; //  정상적으로 종료 시 status는 0
	printf("%s: exit(%d)\n", cur->name, status);
	thread_exit();
}

bool create(const char *file, unsigned initial_size) {
	return filesys_create(file, initial_size);
}

bool remove(const char *file) {
	return filesys_remove(file);
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

	process_close_file(fd);
	fileptr = process_get_file(fd);
	file_close(fileptr);
}

int filesize(int fd) {

	struct thread *curr;
	struct file *fileptr;
	
	curr = thread_current();
	fileptr = curr->fdt[fd];

	// 성공 시 파일의 크기를 반환, 실패 시 -1 반환
	return file_length(fileptr) > 0 ? file_length(fileptr) : -1;
}

int read(int fd, void *buffer, unsigned size) {

}

/* 주소 값이 유저 영역에서 사용하는 주소 값인지 확인하는 함수 */
void check_address(void *addr) {
	if(!is_user_vaddr(addr))
		exit(-1);
}
// 필요한 것인가???
// void get_argument(void *esp, int *arg, int count) {

// }
