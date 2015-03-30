/************************************************************************
xxx
All rights reserved.

File Name:
Summary:
Current Version:
Author:

History:
Ver 1.0.0, Zexus, 2015.03.24
Add “switch windows” function for recording

Ver 0.0.0, xx, 2015.03.24
Original version

**************************************************************************/

#ifndef ELF_UTIL_H_
#define ELF_UTIL_H_

#include <sys/types.h>
#include <stdint.h>
#include <link.h>

unsigned long* image_start_addr(pid_t pid);

// it's OK that we did't get the entry_value if (lazy bind && not referenced yet). we just find the entry_addr and modify it
int find_func_by_got(pid_t pid, const char* name, unsigned long* entry_addr, unsigned long* entry_value);

#if !defined(ANDROID)
// *value is link_map*. don't get confused. use like this: get_linkmap(pid, &value); link_map*plm = (struct link_map*)value;
int get_linkmap(pid_t pid, unsigned long *value);
// this will walk through the link chain. if module_name is null, find in each module, otherwise, find only in module whose name is module_name.
int find_func_by_links(pid_t pid, const struct link_map* plm, const char* name, const char* module_name, unsigned long *value);
// find in one link.
int find_func_in_link(pid_t pid, const struct link_map* plm, const char* name, unsigned long *value);
#endif

// if you are sure the symbol you want to find is in the same so which is loaded by both local and remote process.
// this functions do much less than find by got or link.
void* find_func_by_module_base(pid_t pid, const char* module_name, void* local_addr);

int find_pid_of(const char*process_name);

void* get_module_base(pid_t pid, const char* module_name);

// TODO how to determine use REL or RELA ?
#if defined(ANDROID)
// #error "TODO"
// tangqieTODO
// #define REL_TYPE Rel
#elif defined (LINUX)
#if __WORDSIZE == 64
#define REL_TYPE Rela
#else
#define REL_TYPE Rel
#endif
#endif

#if defined (ANDROID)
#define ELFW_R(type) ELF64_R_##type
#else
#define ELFW_R(type) _ELFW_R(__ELF_NATIVE_CLASS, type)
#define _ELFW_R(w, type) _ELFW_R_1(w, type)
#define _ELFW_R_1(w, type) ELF##w##_R_##type
#endif

extern const char *LIBC_PATH;
extern const char *LINKER_PATH;

#endif /* ELF_UTIL_H_ */
