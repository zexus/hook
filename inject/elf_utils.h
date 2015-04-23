#ifndef ELF_UTIL_H_
#define ELF_UTIL_H_

int find_func_by_got(pid_t pid, const char* name, unsigned long* entry_addr, unsigned long* entry_value);

#endif /* ELF_UTIL_H_ */