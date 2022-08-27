#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H
#include "threads/thread.h"
#include "lib/user/syscall.h"
#include "threads/synch.h"
							 

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
enum pload_status_t 
{LOADING,
	SUCCESS,
	FAIL}

struct process 
{pid_t pid;
	enum pload_status_t load_status;
	struct list_elem ptr;
	struct semaphore wait;
	struct sempaphore load;
	bool waited;
	int exit_code;}
#endif /* userprog/process.h */
