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
#include "syscalls.h"
#include "syscallents.h"
#include <assert.h>
#include <limits.h>

/* Macros */

#define PERM_DENIED (-EACCES)
#define offsetof(a, b) __builtin_offsetof(a,b)
#define get_reg(child, name) __get_reg(child, offsetof(struct user, regs.name))

long __get_reg(pid_t child, int off) {
    long val = ptrace(PTRACE_PEEKUSER, child, off);
    assert(errno == 0);
    return val;
}

struct sandbox {
  pid_t child;
  const char *progname;
};

struct file_permissions {
	char filename[NAME_MAX];
    int readf;
    int writef;
    int execf;
};

struct sandb_syscall {
  int syscall;
  void (*callback)(struct sandbox*, struct user_regs_struct *regs);
  char name[10];
};

/* call numbers are in usr/include/x86_64-linux-gnu/asm/unistd_64.h */

struct sandb_syscall sandb_syscalls[] = {
  {__NR_read,            NULL, "read"    },
  {__NR_write,           NULL, "write"   },
  {__NR_exit,            NULL, "exit"    },
  {__NR_brk,             NULL, "brk"     },
  {__NR_mmap,            NULL, "mmap"    },
  {__NR_access,          NULL, "access"  },
  {__NR_open,            NULL, "open"    },
  {__NR_fstat,           NULL, "fstat"   },
  {__NR_close,           NULL, "close"   },
  {__NR_mprotect,        NULL, "mprotect"},
  {__NR_munmap,          NULL, "munmap"  },
  {__NR_arch_prctl,      NULL, "arch"    },
  {__NR_exit_group,      NULL, "exit_grp"},
  {__NR_getdents,        NULL, "getdent" },
};

/*
struct sandb_syscall sandb_readcalls[] = {
  {__NR_read,            NULL, "read"    },
  {__NR_write,           NULL, "write"   },
  {__NR_brk,             NULL, "brk"     },
  {__NR_mmap,            NULL, "mmap"    },
  {__NR_access,          NULL, "access"  },
  {__NR_open,            NULL, "open"    },
  {__NR_fstat,           NULL, "fstat"   },
  {__NR_close,           NULL, "close"   },
  {__NR_mprotect,        NULL, "mprotect"},
  {__NR_munmap,          NULL, "munmap"  },
  {__NR_arch_prctl,      NULL, "arch"    },
  {__NR_exit_group,      NULL, "exit_grp"},
  {__NR_getdents,        NULL, "getdent" },
};
struct sandb_syscall sandb_writecalls[] = {
  {__NR_read,            NULL, "read"    },
  {__NR_write,           NULL, "write"   },
  {__NR_brk,             NULL, "brk"     },
  {__NR_mmap,            NULL, "mmap"    },
  {__NR_access,          NULL, "access"  },
  {__NR_open,            NULL, "open"    },
  {__NR_fstat,           NULL, "fstat"   },
  {__NR_close,           NULL, "close"   },
  {__NR_mprotect,        NULL, "mprotect"},
  {__NR_munmap,          NULL, "munmap"  },
  {__NR_arch_prctl,      NULL, "arch"    },
  {__NR_exit_group,      NULL, "exit_grp"},
  {__NR_getdents,        NULL, "getdent" },
};

struct sandb_syscall sandb_execcalls[] = {
  {__NR_read,            NULL, "read"    },
  {__NR_write,           NULL, "write"   },
  {__NR_brk,             NULL, "brk"     },
  {__NR_mmap,            NULL, "mmap"    },
  {__NR_access,          NULL, "access"  },
  {__NR_open,            NULL, "open"    },
  {__NR_fstat,           NULL, "fstat"   },
  {__NR_close,           NULL, "close"   },
  {__NR_mprotect,        NULL, "mprotect"},
  {__NR_munmap,          NULL, "munmap"  },
  {__NR_arch_prctl,      NULL, "arch"    },
  {__NR_exit_group,      NULL, "exit_grp"},
  {__NR_getdents,        NULL, "getdent" },
};

*/

/*
 * Referenced Code Start ::
 *
 * Code below till Referenced Code End has been taken from 
 * https://github.com/nelhage/ministrace/blob/master/ministrace.c
 *
 */

const char *syscall_name(int scn) {
    struct syscall_entry *ent;
    static char buf[128];
    if (scn <= MAX_SYSCALL_NUM) {
        ent = &syscalls[scn];
        if (ent->name)
            return ent->name;
    }
    snprintf(buf, sizeof buf, "sys_%d", scn);
    return buf;
}

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

char *read_string(pid_t child, unsigned long addr) {
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

void print_syscall_args(pid_t child, int num) {
    struct syscall_entry *ent = NULL;
    int nargs = SYSCALL_MAXARGS;
    int i;
    char *strval;

    if (num <= MAX_SYSCALL_NUM && syscalls[num].name) {
        ent = &syscalls[num];
        nargs = ent->nargs;
    }
    for (i = 0; i < nargs; i++) {
        long arg = get_syscall_arg(child, i);
        int type = ent ? ent->args[i] : ARG_PTR;
        switch (type) {
        case ARG_INT:
            fprintf(stderr, "%ld", arg);
            break;
        case ARG_STR:
            strval = read_string(child, arg);
            fprintf(stderr, "\"%s\"", strval);
            free(strval);
            break;
        default:
            fprintf(stderr, "0x%lx", arg);
            break;
        }
        if (i != nargs - 1)
            fprintf(stderr, ", ");
    }
}

void print_syscall(pid_t child) {
    int num;
    num = get_reg(child, orig_rax);
    assert(errno == 0);

    fprintf(stderr, "%s(", syscall_name(num));
    print_syscall_args(child, num);
    fprintf(stderr, ") = \n");
}


/* 
 * Referenced Code End 
 */


void sandb_kill(struct sandbox *sandb) {
  kill(sandb->child, SIGKILL);
  wait(NULL);
  exit(EXIT_FAILURE);
}

void denychild(struct sandbox *sandb, struct user_regs_struct *regs)
{
	regs->rax = PERM_DENIED;
	ptrace(PTRACE_SETREGS, sandb->child, 0, regs);
    return;
}

void sandb_handle_syscall(struct sandbox *sandb) {
  int i;
  struct user_regs_struct regs;
  
  char message[10000];
  int j = 0;
  long temp_long;
  char* temp_char2 = message;
  
  memset(message, 0, sizeof(message));
  if(ptrace(PTRACE_GETREGS, sandb->child, NULL, &regs) < 0)
     err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_GETREGS:");
  
  print_syscall(sandb->child);
 /*
  if (regs.orig_rax == __NR_read) {
 
      denychild(sandb, &regs);
      return;
  }
  */
  
  for(i = 0; i < sizeof(sandb_syscalls)/sizeof(*sandb_syscalls); i++) {
      if(regs.orig_rax == sandb_syscalls[i].syscall) {
         //printf("Executed syscall %s \n",sandb_syscalls[i].name); 
         if(sandb_syscalls[i].callback != NULL)
            sandb_syscalls[i].callback(sandb, &regs);
         return;
      }
  }

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

int main(int argc, char **argv) {
  struct sandbox sandb;

  if(argc < 2) {
     errx(EXIT_FAILURE, "[SANDBOX] Usage : %s <elf> [<arg1...>]", argv[0]);
  }

  sandb_init(&sandb, argc-1, argv+1);

  for(;;) {
    sandb_run(&sandb);
  }
  return EXIT_SUCCESS;
}
