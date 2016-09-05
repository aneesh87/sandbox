#include <sys/ptrace.h>
#include <bits/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <err.h>
/* /usr/include/x86_64-linux-gnu/sys/user.h */
#include <sys/user.h>
#include <asm/ptrace.h>
#include <sys/wait.h>
#include <asm/unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/reg.h>
#include <assert.h>
#include <limits.h>
#include <fcntl.h>

/* Macros */

#define PERM_DENIED (-EACCES)
#define offsetof(a, b) __builtin_offsetof(a,b)
#define get_reg(child, name) __get_reg(child, offsetof(struct user, regs.name))

#define MAX_PATH 512

// globals

// 0 indicates entry and 1 indicates exit
int syscall_flag = 0;

// saved is edited out part of string
char *saved =  NULL;

long __get_reg(pid_t child, int off) {
    long val = ptrace(PTRACE_PEEKUSER, child, off);
    assert(errno == 0);
    return val;
}

struct sandbox {
  pid_t child;
  const char *progname;
};

struct tuple {
    int readf;
    int writef;
    int execf;
};
struct file_permissions {
	char filename[MAX_PATH];
    struct tuple perm;
};

struct file_permissions * ftable = NULL;

int file_entries = 0;
/* Note: call numbers are in usr/include/x86_64-linux-gnu/asm/unistd_64.h */

/* IMPORTANT !
 * Referenced Code Start ::
 *
 * Code below till <Referenced Code End Comment> has been adapted from 
 * https://github.com/nelhage/ministrace/blob/master/ministrace.c
 * and other sources as mentioned.
 */

long get_syscall_arg(pid_t child, int which) {
    switch (which) {

    case 0: return get_reg(child, rdi);
    case 1: return get_reg(child, rsi);
    case 2: return get_reg(child, rdx);
    case 3: return get_reg(child, r10);
    case 4: return get_reg(child, r8);
    case 5: return get_reg(child, r9);

    default: return -1L;
    }
}

/* edit string adapted from http://www.linuxjournal.com/article/6100?page=0,2 */

void edit_string(pid_t child,
                 unsigned long addr, char * newstr) 
{
    union u {
            long val;
            char chars[8];
    }data;

    strncpy(data.chars, newstr, 8);
    //data.chars[strlen(newstr)] = '\0';

    ptrace(PTRACE_POKEDATA, child,
               addr, data.val);
    return;
}
char *read_string(pid_t child, unsigned long addr) 
{
    char *val = malloc(4096);
    int allocated = 4096;
    int read = 0;
    unsigned long tmp;
    while (1) {
        if (read + sizeof tmp > allocated) {
            allocated *= 2;
            val = realloc(val, allocated);
        }
        tmp = ptrace(PTRACE_PEEKDATA, child, addr + read);
        if(errno != 0) {
            val[read] = 0;
            break;
        }
        memcpy(val + read, &tmp, sizeof tmp);
        if (memchr(&tmp, 0, sizeof tmp) != NULL)
            break;
        read += sizeof tmp;
    }
    return val;
}

/* Adapted from http://www.geeksforgeeks.org/wildcard-character-matching/ */

int match(char *first, char * second)
{
    if (*first == '\0' && *second == '\0')
        return 1;

    if (*first == '*' && *(first+1) != '\0' && *second == '\0')
        return 0;

    if (*first == '?' || *first == *second)
        return match(first+1, second+1);

    if (*first == '*')
        return match(first+1, second) || match(first, second+1);
    return 0;
}


/* 
 * Referenced Code End 
 */

struct tuple * match_pattern(char * file) {
	/* dummy for now 
	if (strcmp(pattern, "foobar1234") == 0)
		return 1;
    */

    int i;
    int len = 0;
    int index = -1;
    for (i=0; i<file_entries; i++) {
    	char * pattern = ftable[i].filename;
    	if (match(pattern, file)) {
    	//printf("%s  %s\n", pattern,file);
    		if (strlen(pattern) >= len) {
    			len = strlen(pattern);
    			index = i;
    		}
    	}
    }
	if (index != -1) {
		printf("%s is Matched\n", ftable[index].filename);
		return &ftable[index].perm;
	} else {
		return NULL;
	}
}

void syscall_decode(pid_t child, int num) {
 
    long arg;   // address arg
    long flags;
    int readf =  0;  // read flag
    int writef = 0; // write flag
    int execf =  0;  // exec flag 
    char * strval = NULL;
    
    /* switch to get address of string argument(s) */
    switch (num) {
    	case __NR_open:
    	case __NR_stat:
    	case __NR_lstat:

    		arg = get_syscall_arg(child, 0);
    		break;
    	default:
    	    break;
    }
    /* switch to get/set flags */ 
    switch (num) {
        case __NR_open:
            flags = get_syscall_arg(child,1) & O_ACCMODE;
            if (flags == O_RDONLY) {
            	readf = 1;
            } else if (flags == O_WRONLY) {
            	writef = 1;
            } else { /* O_RDWR */
            	readf = 1;
            	writef = 1;
            }
            break;
        default:
            break;
    }
    /* switch to process */
    switch (num) {
   
        case __NR_open:
       // case __NR_stat:
        //case __NR_lstat:
        	
            strval = read_string(child, arg);
            //fprintf(stderr, "%s\n", strval);
            if (!syscall_flag) {
            	struct tuple * access = match_pattern(strval);
                if ((access != NULL) && 
                	((!access->readf && readf) || (!access->writef && writef))) {

                	saved =(char *) calloc(9, sizeof(char));
                	strncpy(saved, strval, 8);
                	saved[8] = '\0';
                	//fprintf(stderr, "%s\n", saved); 
            	    edit_string(child, arg, "ane.c");
            	} 
            } else {

                     if(strcmp(strval, "ane.c") == 0) {

                     	edit_string(child, arg, saved);
                     	free(saved);
                     	saved = NULL;
                     	//fprintf(stderr, "%s %s\n",  saved, read_string(child, arg));
                     	/*
                     	if (get_reg(child, rax) != PERM_DENIED) {
               
                            struct user_regs_struct regs;
                            if(ptrace(PTRACE_GETREGS, child, NULL, &regs) < 0)
                               err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_GETREGS:");
                         
                            regs.rax = PERM_DENIED;
	                     
	                        if (ptrace(PTRACE_SETREGS, child, 0, &regs) < 0) 
	                      	    err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_GETREGS:");
                        }*/

                     } 
            }
            free(strval);
            break;
        default:
            break;
    }
  
}

void sandb_kill(struct sandbox *sandb) {
  kill(sandb->child, SIGKILL);
  wait(NULL);
  exit(EXIT_FAILURE);
}

void sandb_handle_syscall(struct sandbox *sandb) {
  int num = get_reg(sandb->child, orig_rax);
  syscall_decode(sandb->child, num);
 
}

void sandb_init(struct sandbox *sandb, int argc, char **argv) {
  pid_t pid;

  pid = fork();
  
  if(pid == -1) {
     err(EXIT_FAILURE, "[SANDBOX] Error on fork:");
  }
  if (pid == 0) {
      /* child */
      if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
         err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_TRACEME:");

      if(execvp(argv[0], argv) < 0) {
         printf("%s\n", argv[0]);
         err(EXIT_FAILURE, "[SANDBOX] Failed to execv:");
      }
  } else {
      /* Parent */
      sandb->child = pid;
      sandb->progname = argv[0];
      wait(NULL);
  }
}

void sandb_run(struct sandbox *sandb) {
  int status;

  if(ptrace(PTRACE_SYSCALL, sandb->child, NULL, NULL) < 0) {
     if (errno == ESRCH) {
         waitpid(sandb->child, &status, __WALL | WNOHANG);
         sandb_kill(sandb);
     } else {
         err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_SYSCALL:");
     }
  }

  wait(&status);

  if(WIFEXITED(status)) {
     exit(EXIT_SUCCESS);
  }

  if(WIFSTOPPED(status)) {
     sandb_handle_syscall(sandb);
  }

}

void parse_file(FILE * fp)
{
   char line[MAX_PATH];
   int num_lines = 0;
   while(fgets(line, MAX_PATH, fp) != NULL) {
	 /* get a line, up to 512 chars from fp  */
       num_lines++;
   }
   fseek(fp, 0, SEEK_SET);
   printf("Number of lines = %d\n", num_lines);
   ftable = (struct file_permissions *)
            calloc(num_lines, sizeof(struct file_permissions)); 
   int i = 0;	
   while(fgets(line, MAX_PATH, fp) != NULL) {
	 /* get a line, up to 512 chars from fp */
	    char *token=strtok(line," \n\t");
	    if (token != NULL) {
	    	ftable[i].perm.readf  = (token[0] - '0');
	    	ftable[i].perm.writef = (token[1] - '0');
	    	ftable[i].perm.execf  = (token[2] - '0');
	    	token=strtok(NULL," \n\t");
	    	if (token != NULL) {
	    		strncpy(ftable[i].filename, token, MAX_PATH);
	    	}
	    	//printf("%s %d%d%d\n", ftable[i].filename, ftable[i].perm.readf, ftable[i].perm.writef, ftable[i].perm.execf);
	    	i = i + 1;
	    }
   }
   file_entries = i;
   //printf("File Enteries = %d", i);
   return;
}
int main(int argc, char **argv) {
  struct sandbox sandb;
  char path[4096];
  FILE * fp;

  open("ane.c", O_RDWR|O_CREAT, 0000);

  if(argc < 2) {
     errx(EXIT_FAILURE, "[SANDBOX] Usage : %s <-c config_file> <elf> [<arg1...>]", argv[0]);
  }

  if (strcmp(argv[1],"-c") == 0) {
  	  if (argc < 3)
  	  	  errx(EXIT_FAILURE, "Must provide a config file.");
      fp = fopen(argv[2], "r");
      if (fp == NULL) {
          errx(EXIT_FAILURE, "Unable to open config file");
      }
      sandb_init(&sandb, argc-3, argv+3);
  } else {
       fp = fopen(".fendrc", "r");
       if (fp == NULL) {
           strcpy(path,getenv("HOME"));
           strcat(path,"/.fendrc");
       	   fp = fopen(path,"r");
       	   if (fp == NULL)
       	   	errx(EXIT_FAILURE, "Must provide a config file.");
       }
       sandb_init(&sandb, argc-1, argv+1);
  }
  parse_file(fp);
  for(;;) {
    sandb_run(&sandb);
    syscall_flag = ~syscall_flag;
  }
  return EXIT_SUCCESS;
}
