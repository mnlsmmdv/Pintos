#include "userprog/syscall.h"
#include <stdio.h>
#include "userprog/process.h"
#include "userprog/pagedir.h"	
#include "userprog/syscall.h"						 
#include <syscall-nr.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
							 				 
struct file_descriptor{
	struct file *file_struct;
	struct list_elem elem;
};	
				  
static uint32_t *esp;					 
static void syscall_handler (struct intr_frame *);
static bool is_valid_uvaddr (const void *);
static struct file_descriptor *get_open_file (int);	
static int allocate_fd (void);	   
static void close_open_file (int);
static int allocate_fd (void);

//start system call functions 
static void halt(void);
static bool create(const char*, unsigned);
static int open(const char *);
static void close(int);
static int read(int, void *, unsigned);
static int write(int, const void *, unsigned);
static pid_t exec(const char *);
static int wait(pid_t);
static void seek(int, unsigned);
static int filesize(int);
static void exit(int);
static bool remove(const char *);
static unsigned tell(int);

// end system call functions
void syscall_init (void) {
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
    lock_init (&fs_lock);
  list_init (&open_files); 					   
}

static void syscall_handler (struct intr_frame *f){
if (!is_valid_ptr (esp) || !is_valid_ptr (esp + 1) || !is_valid_ptr (esp + 2) || !is_valid_ptr (esp + 3)){
    exit(-1);
    }
	
	else{
		int syscall_number = *esp;
		
		if (syscall_number == SYS_HALT){
            halt();
        }
        else if (syscall_number == SYS_EXIT) {
          exit(*(esp + 1));
        }
        else if (syscall_number == SYS_REMOVE){
            f->eax = remove((char *) *(esp + 1));
        }
        else if (syscall_number == SYS_TELL){
            f->eax = tell(*(esp + 1));
        }
        else if (syscall_number == SYS_CLOSE){
            close(*(esp + 1));
        }
        else if (syscall_number == SYS_FILESIZE){
	        f->eax = filesize(*(esp + 1));
        }
        else if (syscall_number == SYS_OPEN){
            f->eax = open((char *) *(esp + 1));
        }
        else if (syscall_number == SYS_READ){
            f->eax = read(*(esp + 1), (void *) *(esp + 2), *(esp + 3));
        }
        else if (syscall_number == SYS_WRITE){
            f->eax = write(*(esp + 1), (void *) *(esp + 2), *(esp + 3));
        }
		else if (syscall_number == SYS_CREATE){
            f->eax = create((char *) *(esp + 1), *(esp + 2));
        }
        else if (syscall_number == SYS_EXEC){
            f->eax = exec((char *) *(esp + 1));
        }
        else if (syscall_number == SYS_WAIT){
            f->eax = wait(*(esp + 1));
        }
        else if (syscall_number == SYS_SEEK){
            seek(*(esp + 1), *(esp + 2));
        }
        else{
            break;
        }
	}
}
	
// system call functions 
/*
function - hault()
this function is use to stop operating system. parameter used 
in this fuction is void and there is no returns.
*/
void halt(void){
    shutdown_power_off();				 
}

/*
function - create()
this function is used to create a new file. parameters used
in this function are char *file and unsigned initial_size.
this function returns to present_current_state
*/
bool create(const char *file, unsigned initial_size){
    bool present_current_state;

    if (!is_valid_ptr (file))
        exit (-1);

    lock_acquire(&fs_lock);

    status = filesys_create(file, initial_size); 

    lock_release(&fs_lock);

    return present_current_state;
}

/*
function - open()
this function is used to open a file. 
parameters used in this function are char* and file
this function returns present_current_state
*/
int open(const char *file){
    struct file *node_of_file;
    struct file_descriptor *file_description;
    int present_current_state = -1;
  
    if (!is_valid_ptr (file))
        exit(-1);

    lock_acquire (&fs_lock); 
 
	node_of_file = filesys_open(file);
  
    if (node_of_file != NULL){
        file_description = calloc(1, sizeof *fd);
        file_description->fd_num = allocate_fd();
        file_description->owner = thread_current()->tid;
        file_description->file_struct = node_of_file;

        list_push_back(&open_files, &file_description->elem);

        present_current_state = file_description->fd_num;
    }

    lock_release(&fs_lock);
    return present_current_state;
}

/*
function - close()
in this function is used to close file
parameter used in this function is int fd
this function returns none
*/
void close(int fd){
    struct file_descriptor *discription_of_file;

    lock_acquire(&fs_lock); 
    
    discription_of_file = get_open_file(fd);

    if (*discription_of_file != NULL && discription_of_file->owner == thread_current()->tid)
        close_open_file(fd);

    lock_release(&fs_lock);

    return ; 
}

/*
function - read()
in this function data is read into a buffer
parameters used in this function are int fd, void buffer and unsigned size
this function returns present_current_state
*/
int read(int fd, void *buffer, unsigned size){
    struct file_descriptor *discription_of_file;
    int present_current_state = 0;

    struct thread *present_thread = thread_current();

    unsigned cache_memory = size;
    void * temporary_buffer = buffer;

  //Confirm that the memory referred to the buffer is empty.
    while (temporary_buffer != NULL){
        if (!is_valid_uvaddr(temporary_buffer))
        exit (-1);

        if (pagedir_get_page(t->pagedir, temporary_buffer) == NULL)   { 
            struct suppl_pte *spte;

            spte = get_suppl_pte(&t->suppl_page_table, pg_round_down(temporary_buffer));

        if (spte != NULL && !spte->is_loaded)
            load_page(spte);

        else if (spte == NULL && temporary_buffer >= (esp - 32))
            grow_stack(temporary_buffer);

        else
            exit(-1);
        }
        
        //go ahead
        if (cache_memory == 0){
            temporary_buffer = NULL;
        }

        //end
        else if (cache_memory > PGSIZE){
            temporary_buffer = temporary_buffer + PGSIZE;
            cache_memory = cache_memory - PGSIZE;
        }
        
        else{
            temporary_buffer = buffer + size - 1;
            cache_memory = 0;
        }
    }

    lock_acquire(&fs_lock);  

    if (fd == STDOUT_FILENO)
        present_current_state = -1;
        
    else if (fd == STDIN_FILENO){
        uint8_t c;
        unsigned tally = size;
        uint8_t *cache_node = buffer;

        while (tally > 1 && (c = input_getc()) != 0){
            *cache_node = c;
            buffer++;
            tally--; 
            }

        *cache_node = 0;
        present_current_state = size - tally;
    }

    else{
        discription_of_file = get_open_file(fd);

        if (discription_of_file != NULL)
            present_current_state = file_read(discription_of_file->file_struct, buffer, size);
    }

    lock_release(&fs_lock);

    return present_current_state;
}

/*
function - write()
in this function is used to write things from buffer to file
parameters used in this function are int fd, void buffer and unsigned size
this function returns present_current_state
*/
int write(int fd, const void *buffer, unsigned size){
    struct file_descriptor *discription_of_file;  
    int present_current_state = 0;

    unsigned cache_memory = size;
    void *temporary_buffer = buffer;

    //Verify the memory referred to the buffer is empty.
    while (temporary_buffer != NULL)
    {
        if (!is_valid_ptr(temporary_buffer))
	        exit (-1);
      
        //go ahead
        if (cache_memory > PGSIZE){
            temporary_buffer =  temporary_buffer + PGSIZE;
            cache_memory = cache_memory - PGSIZE;
	    }

        else if (cache_memory == 0){
            //end
            temporary_buffer = NULL;
	    }
        
        else{
            temporary_buffer = buffer + size - 1;
            cache_memory = 0;
        }
    }

    lock_acquire(&fs_lock); 

    if (fd == STDIN_FILENO){
        present_current_state = -1;
    }

    else if (fd == STDOUT_FILENO){
        putbuf(buffer, size);;
        present_current_state = size;
    }

    else {
        discription_of_file = get_open_file(fd);

        if (discription_of_file != NULL)
            present_current_state = file_write(discription_of_file->file_struct, buffer, size);
    }
    
    lock_release(&fs_lock);

    return present_current_state;
}

/*
function - pid_t exec()
this function is used to create a new file. parameter used
in this function is char *cmd_line
this function returns to tid
*/
pid_t exec(const char *cmd_line){
    //stores thread id and assigned to pid
    tid_t tid;
    struct thread *present_thread;

    //validates the pointer
    if (!is_valid_ptr(cmd_line))
    {
        exit(-1);
    }

    present_thread = thread_current();
    present_thread->child_load_status = 0;

    tid = process_execute(cmd_line);

    lock_acquire(&cur->lock_child);

    while (present_thread->child_load_status == 0)
        cond_wait(&cur->cond_child, &present_thread->lock_child);

    if (present_thread->child_load_status == -1)
        tid = -1;

    lock_release(&present_thread->lock_child);

    return tid;
}

/*
function - wait()
parameter used in this function is pid_t pid
this function returns process_wait(pid)
*/
int wait(pid_t pid){ 
  return process_wait(pid);
}

/*
function - seek()
parameters used in this function are int fd, unsigned current_state
this function returns nothing
*/
void seek(int fd, unsigned current_state){
    struct file_descriptor *discription_of_file;

    lock_acquire(&fs_lock); 

    discription_of_file get_open_file(fd);

    if (discription_of_file != NULL)
        file_seek(discription_of_file->file_struct, current_state);

    lock_release(&fs_lock);
    
    return;
}

/*
function - filesize()
this function is used find the size of the file. 
parameter used in this function is int fd
this function returns present_current_state
*/
int filesize(int fd){
    struct file_descriptor *discription_of_file;
    int present_current_state = -1;

    lock_acquire(&fs_lock);

    discription_of_file = get_open_file (fd);

    if (discription_of_file != NULL)
        present_current_state = file_length (discription_of_file->file_struct);

    lock_release(&fs_lock);

    return present_current_state;
}

/*
function - exit()
in this function is used to end the currently active thread
parameters used in this function are int and status
this function returns null
*/
void exit(int status){
    struct child_status *offspring;
    struct thread *present_thread = thread_current();

    //print the exit message
    printf ("%s: exit(%d)\n", present_thread->name, status);

    struct thread *parentThread = thread_get_by_id(present_thread->parent_id);

    if (parentThread!= NULL) {
      struct list_elem *e = list_tail(&parentThread->children);
      while ((e = list_prev (e)) != list_head(&parentThread->children))
        {
          child = list_entry(e, struct child_status, elem_child_status);

          if (offspring->child_id == present_thread->tid)
          {
            lock_acquire(&parentThread->lock_child);

            offspring->is_exit_called = true;
            offspring->child_exit_status = status;

            lock_release(&parentThread->lock_child);
          }
        }
    }
    thread_exit();
}

/*
function - remove()
in this function is used to remove the file
parameters used in this function are char *file
this function present_current_state
*/
bool remove(const char *file){
    bool present_current_state;
 
    if (!is_valid_ptr(file)){
        // ...To Implement...
    }
}

/*
function - tell()
in this function is used to Obtain a file's current location
parameter used in this function is int fd
this function returns current_state
*/
unsigned tell(int fd){
    int current_state = 0;
    struct file_descriptor *discription_of_file;

    lock_acquire(&fs_lock); 
    discription_of_file = get_open_file(fd);

    if (fd_struct != NULL)
        current_state = file_tell discription_of_file->file_struct;

    lock_release(&fs_lock);

    return current_state 
}
// end of system calls										   
