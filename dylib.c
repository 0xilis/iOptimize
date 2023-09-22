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
 /* now, modify code... (improve this later to be more dynamic rather than manually patching instructions, ex look at the top two instructions and calculate the change rather than hardcoding, would be more future-proof, but this should suffice for now) */
 /*
 Original code:
cbz x0, #0x18 ; C0 00 00 B4
cbz x1, #0x18 ; A1 00 00 B4
ldr x8, [x0] ; 08 00 40 F9
and x0, x8, #0x7ffffffffffff8 ; 00 CD 7D 92
cbz x0, loc_3fb0 ; 40 00 00 B4
b __class_getVariable ; F9 44 00 14
mov x0, #0x0 ; 00 00 80 D2
ret ; C0 03 5F D6

  New code:
cbz x0, #0x14 ; A0 00 00 B4
cbz x1, #0x14 ; 81 00 00 B4
ldr x8, [x0] ; 08 00 40 F9
and x0, x8, #0x7ffffffffffff8 ; 00 CD 7D 92
cbnz x0, __class_getVariable ; 40 9F 08 B5
mov x0, #0x0 ; 00 00 80 D2
ret ; C0 03 5F D6
ret ; C0 03 5F D6

this saves us a branch in some scenarios

(we don't need the last ret but we need to ensure every function we modify is the same size so nothing breaks)
  */
 /* TODO: There's probably a more elegant way to do this than to just put a lot of if statements to make sure instructions are exactly the same */
 long long *ptrToInst = origFuncPtr;
 if (*ptrToInst == 0xC00000B4) {
  ptrToInst++;
  if (*ptrToInst == 0xA10000B4) {
   ptrToInst++;
   if (*ptrToInst == 0x080040F9) {
    ptrToInst++;
    if (*ptrToInst == 0x00CD7D92) {
     ptrToInst++;
     if (*ptrToInst == 0x400000B4) {
      ptrToInst++;
      if (*ptrToInst == 0xF9440014) {
       ptrToInst++;
       if (*ptrToInst == 0x000080D2) {
        ptrToInst++;
        if (*ptrToInst == 0xC0035FD6) {
         /* go back to beginning, and start patching */
         ptrToInst = origFuncPtr;
         /* cbz x0, #0x14 */
         *ptrToInst = 0xA00000B4;
         ptrToInst++;
         /* cbz x1, #0x14 */
         *ptrToInst = 0x810000B4;
         ptrToInst++;
         /* ldr x8, [x0] */
         /* *ptrToInst = 0x080040F9; is already this instruction, no need to modify */
         ptrToInst++;
         /* and x0, x8, #0x7ffffffffffff8 */
         /* *ptrToInst = 0x00CD7D92; is already this instruction, no need to modify */
         ptrToInst++;
         /* cbnz x0, __class_getVariable */
         *ptrToInst = 0x409F08B5;
         ptrToInst++;
         /* mov x0, #0x0 */
         *ptrToInst = 0x000080D2;
         ptrToInst++;
         /* ret */
         *ptrToInst = 0xC0035FD6;
         /* no need to modify last ret since we should never reach it */
         /* class_getClassVariable patch done */
        }
       }
      }
     }
    }
   }
  }
 } else if (*ptrToInst == 0xA00000B4) {
  printf("libobjc's class_getClassVariable has already been patched by iOptimize.\n");
 }
}

#ifdef COMPILE_AS_CLI
int main(void) {
 printf("iOptimize: Start applying optimizations...\n");
 /* TODO: may be good idea for the binary to have args, ex something like -optimize to optimize and -revert to revert optimizations if they were applied */
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
