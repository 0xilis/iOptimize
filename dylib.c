/*
 * Copyright (C) 2023 Snoolie K / 0xilis. All rights reserved.
 *
 * This document is the property of Snoolie K / 0xilis.
 * It is considered confidential and proprietary.
 *
 * This document may not be reproduced or transmitted in any form,
 * in whole or in part, without the express written permission of
 * Snoolie K / 0xilis.
*/

/*
to compile dylib:
clang -D COMPILE_TO_INJECT -dynamiclib dylib.c -o arm64.dylib
to compile CLI:
clang -D COMPILE_AS_CLI dylib.c -o ioptimize
*/

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>

__attribute__((always_inline)) static void do_the_magic(void) {
 /* code was re-used from my internal hooking library libsubsidiary, which was helped via https://tfin.ch/blog/HookingCFunctionsAtRuntime.html */
 void *mainProgramHandle = dlopen("/usr/lib/libobjc.A.dylib", RTLD_NOW);
 if (!mainProgramHandle) {
  fprintf(stderr, "dlopen failed: %s\n", dlerror());
  return;
 }
 int64_t *origFuncPtr = dlsym(mainProgramHandle, "class_getClassVariable");
 if (!origFuncPtr) {
  fprintf(stderr, "dlsym %s failed\n", dlerror());
  return;
 }
 size_t pageSize = sysconf(_SC_PAGESIZE);
 uintptr_t start = (uintptr_t)origFuncPtr;
 uintptr_t end = start + 1;
 uintptr_t pageStart = start & -pageSize;
 mprotect((void *)pageStart, end - pageStart, PROT_READ | PROT_WRITE | PROT_EXEC);
 /* made page writable */
 /* now, modify code... (currently using ez method, improve this later to save 1 cycle/instruction via nop-less method) */
 long long originalCbzInstruction = 0x400000B4; /* cbz x0, loc_3fb0 */
 long long *ptrToInst = origFuncPtr;
 /* TODO: Add safety check here so if we can't find the instruction, this won't loop infinitely. */
 while (*ptrToInst != originalCbzInstruction) {
  ptrToInst++;
 }
 *ptrToInst = 0x409F08B5; /* cbnz x0, __class_getVariable */
 ptrToInst++;
 *ptrToInst = 0x1F2003D5; /* nop */
}

#ifdef COMPILE_AS_CLI
int main(void) {
 printf("iOptimize: Start applying optimizations...\n");
 do_the_magic();
 printf("iOptimize: finish\n");
 return 0;
}
#endif

#ifdef COMPILE_TO_INJECT
__attribute__((constructor)) static void init() {
 do_the_magic();
}
#endif
