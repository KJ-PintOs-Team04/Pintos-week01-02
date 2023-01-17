#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/init.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "threads/palloc.h"
#include "userprog/gdt.h"
#include "userprog/process.h"
#include "threads/flags.h"
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/input.h"
#include "lib/stdio.h"
#include "lib/kernel/stdio.h"
#include "lib/string.h"
#include "intrinsic.h"
#include "vm/vm.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
void halt (void);
void exit (int status);
tid_t fork(const char *thread_name, struct intr_frame *if_);
int exec (const char *cmd_line);
int wait (tid_t tid);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int read(int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
static struct page *check_address(void *addr);
static void check_writable_buffer(void *buffer, int size);
static void check_valid_buffer(void *buffer, int size);
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
	lock_init(&filesys_lock);

	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 |
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
	thread_current()->rsp = f->rsp;
	switch (f->R.rax)
	{
		case SYS_HALT:
			halt();
			break;
		case SYS_EXIT:
			exit(f->R.rdi);
			break;
		case SYS_FORK:
			check_address(f->R.rdi);
			f->R.rax = fork(f->R.rdi, f);
			break;
		case SYS_EXEC:
			check_address(f->R.rdi);
			f->R.rax = exec(f->R.rdi);
			break;
		case SYS_WAIT:
			f->R.rax = wait(f->R.rdi);
			break;
		case SYS_CREATE:
			check_address(f->R.rdi);
			f->R.rax = create(f->R.rdi, f->R.rsi);
			break;
		case SYS_REMOVE:
			check_address(f->R.rdi);
			f->R.rax = remove(f->R.rdi);
			break;
		case SYS_OPEN:
			check_address(f->R.rdi);
			f->R.rax = open(f->R.rdi);
			break;
		case SYS_FILESIZE:
			f->R.rax = filesize(f->R.rdi);
			break;
		case SYS_READ:
			check_writable_buffer(f->R.rsi, f->R.rdx);
			f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE:
			check_valid_buffer(f->R.rsi, f->R.rdx);
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_SEEK:
			seek(f->R.rdi, f->R.rsi);
			break;
		case SYS_TELL:
			f->R.rax = tell(f->R.rdi);
			break;
		case SYS_CLOSE:
			close(f->R.rdi);
			break;
		default:
			exit (-1);
			break;
	}
}

void halt(void) {
	power_off();
}

void exit (int status) {
	struct thread *curr = thread_current();
	curr->exit_status =  status;
	if (curr->child) {
		curr->child->exit_status = status;
	} 
	printf("%s: exit(%d)\n", curr->name, status);
	thread_exit();
}

tid_t fork(const char *thread_name, struct intr_frame *if_) {
	return process_fork(thread_name, if_);
}

/* 프로그램을 실행시키는 시스템 콜*/
int exec (const char *cmd_line) {
	
	int size = strlen(cmd_line) + 1;
	char *fn_copy = palloc_get_page(PAL_ZERO);

	if (!fn_copy) {
		exit(-1);
		return -1;
	}

	strlcpy(fn_copy, cmd_line, size);

	if (process_exec(fn_copy) == -1) {
		exit(-1);
		return -1;
	}
}

/* 자식 프로세스가 종료 될 때까지 대기
 * tid: 자식 프로세스 pid, int: 자식 프로세스 상태
 */
int wait (tid_t tid) {
	return process_wait(tid);
}

bool create(const char *file, unsigned initial_size) {
	return filesys_create(file, initial_size);
}

/* 파일이 열려있던지 닫혀있던지 파일을 삭제한다. */
bool remove(const char *file) {
	return filesys_remove(file);
}

/* 파일을 열 때 사용하는 시스템 콜 */
int open(const char *file) {
	struct file *fileptr;
	int fd;
	// root_dir 부터 file(파일 이름)찾아 포인터 반환
	lock_acquire(&filesys_lock);
	fileptr = filesys_open(file);	
	lock_release(&filesys_lock);
	
	// 실패 시 -1 반환
	if (fileptr == NULL)
		return -1;

	// 성공 시 fdt에 fileptr 저장 후 fd 반환
	fd = process_add_file(fileptr);
	if (fd == -1)
		file_close(fileptr);

	return fd;
}

/* 열린 파일을 닫는 시스템 콜 */
void close (int fd) {
	struct file *fileptr = thread_current()->fdt[fd];
	
	if (fileptr) {
		lock_acquire(&filesys_lock);
		file_close(fileptr);
		lock_release(&filesys_lock);
		process_close_file(fd);
	}
}

int filesize(int fd) {
	off_t length;
	struct file *fileptr = thread_current()->fdt[fd];

	// 성공 시 파일의 크기를 반환, 실패 시 -1 반환
	if (fileptr) {
		return file_length(fileptr);
	}
	return -1;
}

/* fd로 열린 파일에서 buffer에(메모리) 저장 */
int read(int fd, void *buffer, unsigned size) {
	off_t byte;
	if (fd == STDOUT_FILENO)
		return -1;

	// reads from keyboard
	if (fd == STDIN_FILENO) {
		lock_acquire(&filesys_lock);
		byte = input_getc();
		lock_release(&filesys_lock);
		return byte;
	}

	struct file *fileptr = thread_current()->fdt[fd];
	// 읽을 file이 있으면 byte 반환
	if (fileptr) {
		lock_acquire(&filesys_lock);
		// Reads SIZE bytes from FILE into BUFFER
		byte = file_read(fileptr, buffer, size);
		lock_release(&filesys_lock);

		return byte;
	}
	return -1;
}

/* 열린 파일(fd)에 버퍼를 write */
int write(int fd, const void *buffer, unsigned size) {
	off_t byte;

	if (fd == STDIN_FILENO)
		return -1;

	if (fd == STDOUT_FILENO) {
		lock_acquire(&filesys_lock);
		putbuf(buffer, size);
		lock_release(&filesys_lock);
		return size;
	}

	struct file *fileptr = thread_current()->fdt[fd];
	if (fileptr) {
		lock_acquire(&filesys_lock);
		byte = file_write(fileptr, buffer, size);
		lock_release(&filesys_lock);
		return byte;
	}
	return -1;
}

/* 열린 파일(fd)의 읽거나 쓸 다음 바이트를 position으로 변경 */
void seek(int fd, unsigned position) {
	struct file *fileptr = thread_current()->fdt[fd];
	if (fileptr)
		file_seek(fileptr, position);
}

/* 열린 파일 fd에서 읽거나 쓸 다음 바이트의 위치를 반환 */
unsigned tell(int fd) {
	struct file *fileptr = thread_current()->fdt[fd];
	if (fileptr)
		return file_tell(fileptr);
}

/* 주소 값이 유저 영역에서 사용하는 주소 값인지 확인하는 함수 */
static struct page *check_address(void *addr) {
	struct thread *t = thread_current();
	if (addr == NULL || is_kernel_vaddr(addr))
		exit(-1);
	return spt_find_page(&t->spt, addr);
}

static void check_writable_buffer (void *buffer, int size) {
	struct page *page;
	int i = 0;
	while (size > 0)
	{
		page = check_address(buffer + PGSIZE * i);
		if (page && !page->writable) {
			exit(-1);
		}
		size -= PGSIZE;
		i++;
	}
}

static void check_valid_buffer (void *buffer, int size) {
	struct page *page;
	int i = 0;
	while (size > 0) {
		page = check_address(buffer + PGSIZE * i);
		if (page)
			size -= PGSIZE;
		else
			exit(-1);
		i++;
	}
}
