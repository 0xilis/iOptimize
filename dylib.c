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

typedef instruction64 long; /* an arm64 intruction takes up 32 bits */

int instEqual(instruction64 *ins, unsigned int insCount, instruction64 *start) {
 instruction64 *ptrToInst = start;
 for (int i = 0; i < insCount; i++) {
  if (*ptrToInst != ins[i]) {
   return 0;
  }
  ptrToInst++;
 }
 return 1;
}

void applyPatch(instruction64 *ins, unsigned int insCount, instruction64 *start) {
 instruction64 *ptrToInst = start;
 for (int i = 0; i < insCount; i++) {
  *ptrToInst = ins[i];
 }
}

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
 instruction64 origCode_class_getClassVariable[8] = {
  0xC00000B4,
  0xA10000B4,
  0x080040F9,
  0x00CD7D92,
  0x400000B4,
  0xF9440014,
  0x000080D2,
  0xC0035FD6
 };
 instruction64 newCode_class_getClassVariable[7] = {
  0xA00000B4,
  0x810000B4,
  0x080040F9,
  0x00CD7D92,
  0x409F08B5,
  0x000080D2,
  0xC0035FD6
 };
 if (instEqual(origCode_class_getClassVariable, 8, origFuncPtr)) {
  applyPatch(newCode_class_getClassVariable, 7, origFuncPtr);
 } else if (instEqual(newCode_class_getClassVariable, 7, origFuncPtr)) {
  printf("libobjc's class_getClassVariable has already been patched by iOptimize.\n");
 } else {
  printf("class_getClassVariable appears to be changed, iOptimize did not optimize\n");
 }

 /* objc_msgSend patch */
 /* saves a mov when we need to objc_msgSend_uncached */
 origFuncPtr = dlsym(mainProgramHandle, "objc_msgSend");
 if (!origFuncPtr) {
  fprintf(stderr, "dlsym %s failed\n", dlerror());
  return;
 }
 instruction64 origCode_objc_msgSend[42] = {
  0x1F0000F1,
  0x4D030054,
  0x0D0040F9,
  0xB0CD7D92, /* x15 version is AF CD 7D 92 */
  0xEF0310AA, /* this is the mov x15, x16 (mov x16, x15 is F0 03 0F AA) */
  0x0A0A40F9, /* x15 version is EA 09 40 F9 */
  0x4BFD70D3,
  0x4ABD4092,
  0x2C000B0A,
  0x4D110C8B,
  0xB125FFA8,
  0x3F0101EB,
  0x61000054,
  0x310210CA, /* eor */
  0x20021FD6,
  0x291300B4,
  0xBF010AEB,
  0x22FFFF54,
  0x4D512B8B,
  0x4C110C8B,
  0xB125FFA8,
  0x3F0101EB,
  0xE0FEFF54,
  0x3F0100F1,
  0xA0114CFA,
  0x68FFFF54,
  0x8E000014,
  0x20010054,
  0x0A084092,
  0x0BFC7793,
  0x5F1D00F1,
  0x6C018A9A,
  0xCA010090,
  0x4A412F91,
  0x50796CF8, /* x15 version is 4F 79 6C F8 */
  0xE1FFFF17,
  0x010080D2,
  0x00E4002F,
  0x01E4002F,
  0x02E4002F,
  0x03E4002F,
  0xC0035FD6
 };
 if (instEqual(origCode_objc_msgSend, 42, origFuncPtr)) {
  /* applyPatch(newCode_objc_msgSend, 42, origFuncPtr); */
 /*} else if (instEqual(newCode_objc_msgSend, 7, origFuncPtr)) {
  printf("libobjc's objc_msgSend has already been patched by iOptimize.\n");*/
 } else {
  printf("objc_msgSend appears to be changed, iOptimize did not optimize\n");
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
