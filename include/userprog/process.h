#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);
struct thread *get_child_process(tid_t tid);
void remove_child_process(tid_t tid);
int process_add_file(struct file *f);
struct file *process_get_file (int fd);
void process_close_file(int fd);
struct file *get_parent_file(int fd, struct file **fdt);
struct thread *get_child_process(tid_t tid);
void remove_child_process(tid_t tid);
void remove_all_child_process(void);
#endif /* userprog/process.h */
