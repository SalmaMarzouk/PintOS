#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/synch.h"
#include "threads/vaddr.h"

static void syscall_handler (struct intr_frame *);
void open_wrapper(struct intr_frame *f,void* esp);
int open (const char *file);
void read_wrapper (struct intr_frame *f,void* esp);
int read (int fd, void *buffer, unsigned size);
struct fd_element* get_fd(int fd);
void validate_void_ptr(const void* pt);


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&files_sync_lock);
}

static void
syscall_handler (struct intr_frame *f) 
{
  //modified
  int sys_code = *(int*)f->esp;
  void *args = f -> esp;
  switch(sys_code){
       case SYS_HALT:
            break;
       case SYS_EXIT:
           exit_wrapper(f->esp);
           break;
       case SYS_EXEC:
           
           break;
       case SYS_WAIT:
          
           break;
       case SYS_CREATE:
       
           break;
       case SYS_REMOVE:
       
           break;
       case SYS_OPEN:
           open_wrapper(f,f->esp);
           break;
       case SYS_FILESIZE:
       
           break;
       case SYS_READ:
           read_wrapper(f,f -> esp);
           break;
       case SYS_WRITE:
           write_wrapper(f -> esp);
           break;
       case SYS_SEEK:

           break;
       case SYS_TELL:

           break;
       case SYS_CLOSE:

           break;
}
}

void open_wrapper(struct intr_frame *f,void* esp){
    void* valid = (void*)(*((int*)esp+1));
    validate_void_ptr(valid);
    f -> eax = open((const char *)(*((int*)esp+1)));
}
int open (const char *file){
    int fd = -1;    //returned if the file could not be opened.
    lock_acquire(&files_sync_lock);
    struct thread *current = thread_current ();
    struct file * opened_file = filesys_open(file);
    lock_release(&files_sync_lock);
    if(opened_file != NULL)
    {
        current->fd_size = current->fd_size + 1;
        fd = current->fd_size;
        struct fd_element *file = (struct fd_element*) malloc(sizeof(struct fd_element));
        file->fd = fd;
        file->file = opened_file;
        // add the fd_element to the thread fd_list
        list_push_back(&current->fd_list, &file->element);
    }
    return fd;
}

void read_wrapper (struct intr_frame *f,void* esp){
    int fd = *((int*)esp+1);
    void* buffer = (void*)(*((int*)esp+2));
    unsigned size = * ((unsigned*)esp+3);
    validate_void_ptr(buffer);
    validate_void_ptr(buffer+size);
    f->eax = read(fd,buffer,size);
}
int read(int fd, void *buffer, unsigned size){

    int bytes_read = -1;
    if(fd == 0)     //keyboard read
    {
        bytes_read = input_getc();
    }
    else if(fd > 0)     //file read
    {
        struct fd_element *fd_elem = get_fd(fd);
        if(fd_elem == NULL || buffer == NULL)
        {
            return -1;
        }
        //get the file
        struct file *file = fd_elem->file;
        lock_acquire(&files_sync_lock);
        bytes_read = file_read(file, buffer, size);
        lock_release(&files_sync_lock);
        if(bytes_read < (int)size && bytes_read != 0)
        {
            //some error happened
            bytes_read = -1;
        }
    }
    return bytes_read;
}
void write_wrapper(void* esp){
    int fd = *((int*)esp+1);
    void* buffer = (void*)(*((int*)esp+2));
    unsigned size = * ((unsigned*)esp+3);
    validate_void_ptr(buffer);
    if(fd==1){
       putbuf (buffer, (size_t) size);
     }

}

void exit_wrapper(void *esp){
    int status = *((int*)esp+1);
    thread_current()->child_status = status;
    thread_exit();
}


void validate_void_ptr(const void* pt){
    if(!((pt!=NULL)&&(is_user_vaddr(pt))&&(pagedir_get_page (thread_current()->pagedir, pt)!=NULL))){
         thread_exit();
     }
}
struct fd_element* get_fd(int fd)
{
    struct list_elem *e;
    for (e = list_begin (&thread_current()->fd_list); e != list_end (&thread_current()->fd_list);
         e = list_next (e))
    {
        struct fd_element *fd_elem = list_entry (e, struct fd_element, element);
        if(fd_elem->fd == fd)
        {
            return fd_elem;
        }
    }
    return NULL;
}

