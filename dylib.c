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
 /* similar patch can be applied to objc_msgLookup and objc_msgSendSuper2 */
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
 instruction64 newCode_objc_msgSend[42] = {
  0x1F0000F1,
  0x4D030054,
  0x0D0040F9,
  0xAFCD7D92,
  0xEA0940F9,
  0x4BFD70D3,
  0x4ABD4092,
  0x2C000B0A,
  0x4D110C8B,
  0xB125FFA8,
  0x3F0101EB,
  0x81000054,
  0xF0030FAA,
  0x310210CA,
  0x20021FD6,
  0x291300B4,
  0xBF010AEB,
  0x02FFFF54,
  0x4D512B8B,
  0x4C110C8B,
  0xB125FFA8,
  0x3F0101EB,
  0xC0FEFF54,
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
  0x4F796CF8,
  0xE1FFFF17,
  0x010080D2,
  0x00E4002F,
  0x01E4002F,
  0x02E4002F,
  0x03E4002F,
  0xC0035FD6
 };
 if (instEqual(origCode_objc_msgSend, 42, origFuncPtr)) {
  applyPatch(newCode_objc_msgSend, 42, origFuncPtr);
 } else if (instEqual(newCode_objc_msgSend, 42, origFuncPtr)) {
  printf("libobjc's objc_msgSend has already been patched by iOptimize.\n");
 } else {
  printf("objc_msgSend appears to be changed, iOptimize did not optimize\n");
 }

 /* objc_msgSend_uncached patch */
 /* save a mov. the bottom nop is not necessary but we need to have this be the same size */
 origFuncPtr = dlsym(mainProgramHandle, "objc_msgSend_uncached");
 if (!origFuncPtr) {
  fprintf(stderr, "dlsym %s failed\n", dlerror());
  return;
 }
 instruction64 origCode_objc_msgSend_uncached[30] = {
  0xFD7BBFA9,
  0xFD030091,
  0xFF4303D1,
  0xE00700AD,
  0xE20F01AD,
  0xE41702AD,
  0xE61F03AD,
  0xE00708A9,
  0xE20F09A9,
  0xE4170AA9,
  0xE61F0BA9,
  0xE83F0CA9,
  0xF0030FAA,
  0xE20310AA,
  0x630080D2,
  0xED4A0094,
  0xF10300AA,
  0xE00740AD,
  0xE20F41AD,
  0xE41742AD,
  0xE61F43AD,
  0xE00748A9,
  0xE20F49A9,
  0xE4174AA9,
  0xE61F4BA9,
  0xE8434CA9,
  0x10027FB2,
  0xBF030091,
  0xFD7BC1A8,
  0x20021FD6
 };
 instruction64 newCode_objc_msgSend_uncached[30] = {
  0xFD7BBFA9,
  0xFD030091,
  0xFF4303D1,
  0xE00700AD,
  0xE20F01AD,
  0xE41702AD,
  0xE61F03AD,
  0xE00708A9,
  0xE20F09A9,
  0xE4170AA9,
  0xE61F0BA9,
  0xE83F0CA9,
  0xE2030FAA,
  0x630080D2,
  0xED4A0094,
  0xF10300AA,
  0xE00740AD,
  0xE20F41AD,
  0xE41742AD,
  0xE61F43AD,
  0xE00748A9,
  0xE20F49A9,
  0xE4174AA9,
  0xE61F4BA9,
  0xE8434CA9,
  0x10027FB2,
  0xBF030091,
  0xFD7BC1A8,
  0x20021FD6,
  0x1F2003D5
 };
 if (instEqual(origCode_objc_msgSend_uncached, 30, origFuncPtr)) {
  applyPatch(newCode_objc_msgSend_uncached, 30, origFuncPtr);
 } else if (instEqual(newCode_objc_msgSend_uncached, 30, origFuncPtr)) {
  printf("libobjc's objc_msgSend_uncached has already been patched by iOptimize.\n");
 } else {
  printf("objc_msgSend_uncached appears to be changed, iOptimize did not optimize\n");
 }

 /* objc_msgLookup_uncached patch */
 /* same as objc_msgSend_uncached patch. save a mov. */
 origFuncPtr = dlsym(mainProgramHandle, "objc_msgLookup_uncached");
 if (!origFuncPtr) {
  fprintf(stderr, "dlsym %s failed\n", dlerror());
  return;
 }
 instruction64 origCode_objc_msgLookup_uncached[30] = {
  0xFD7BBFA9,
  0xFD030091,
  0xFF4303D1,
  0xE00700AD,
  0xE20F01AD,
  0xE41702AD,
  0xE61F03AD,
  0xE00708A9,
  0xE20F09A9,
  0xE4170AA9,
  0xE61F0BA9,
  0xE83F0CA9,
  0xF0030FAA,
  0xE20310AA,
  0x630080D2,
  0xCD4A0094,
  0xF10300AA,
  0xE00740AD,
  0xE20F41AD,
  0xE41742AD,
  0xE61F43AD,
  0xE00748A9,
  0xE20F49A9,
  0xE4174AA9,
  0xE61F4BA9,
  0xE8434CA9,
  0x10027FB2,
  0xBF030091,
  0xFD7BC1A8,
  0xC0035FD6
 };
 instruction64 newCode_objc_msgLookup_uncached[29] = {
  0xFD7BBFA9,
  0xFD030091,
  0xFF4303D1,
  0xE00700AD,
  0xE20F01AD,
  0xE41702AD,
  0xE61F03AD,
  0xE00708A9,
  0xE20F09A9,
  0xE4170AA9,
  0xE61F0BA9,
  0xE83F0CA9,
  0xE2030FAA,
  0x630080D2,
  0xCD4A0094,
  0xF10300AA,
  0xE00740AD,
  0xE20F41AD,
  0xE41742AD,
  0xE61F43AD,
  0xE00748A9,
  0xE20F49A9,
  0xE4174AA9,
  0xE61F4BA9,
  0xE8434CA9,
  0x10027FB2,
  0xBF030091,
  0xFD7BC1A8,
  0xC0035FD6
 };
 if (instEqual(origCode_objc_msgLookup_uncached, 30, origFuncPtr)) {
  applyPatch(newCode_objc_msgLookup_uncached, 29, origFuncPtr);
 } else if (instEqual(newCode_objc_msgLookup_uncached, 29, origFuncPtr)) {
  printf("libobjc's objc_msgLookup_uncached has already been patched by iOptimize.\n");
 } else {
  printf("objc_msgLookup_uncached appears to be changed, iOptimize did not optimize\n");
 }

 /* cache_getImp patch */
 /* save a mov and branch */
 /* actually current patch does not save mov instr, but that is possible, and current patch does save a branch... */
 origFuncPtr = dlsym(mainProgramHandle, "cache_getImp");
 if (!origFuncPtr) {
  fprintf(stderr, "dlsym %s failed\n", dlerror());
  return;
 }
 instruction64 origCode_cache_getImp[28] = {
  0xF00300AA,
  0xEF0310AA,
  0x0A0A40F9,
  0x4BFD70D3,
  0x4ABD4092,
  0x2C000B0A,
  0x4D110C8B,
  0xB125FFA8,
  0x3F0101EB,
  0xA1000054,
  0xE00311AA,
  0x400000B4,
  0x000010CA,
  0xC0035FD6,
  0x890100B4,
  0xBF010AEB,
  0xE2FEFF54,
  0x4D512B8B,
  0x4C110C8B,
  0xB125FFA8,
  0x3F0101EB,
  0xA0FEFF54,
  0x3F0100F1,
  0xA0114CFA,
  0x68FFFF54,
  0x01000014,
  0x000080D2,
  0xC0035FD6
 };
 instruction64 newCode_cache_getImp[27] = {
  0xF00300AA,
  0xEF0310AA,
  0x0A0A40F9,
  0x4BFD70D3,
  0x4ABD4092,
  0x2C000B0A,
  0x4D110C8B,
  0xB125FFA8,
  0x3F0101EB,
  0xA1000054,
  0xE00311AA,
  0x400000B4,
  0x000010CA,
  0xC0035FD6,
  0x690100B4,
  0xBF010AEB,
  0xE2FEFF54,
  0x4D512B8B,
  0x4C110C8B,
  0xB125FFA8,
  0x3F0101EB,
  0xA0FEFF54,
  0x3F0100F1,
  0xA0114CFA,
  0x68FFFF54,
  0x000080D2,
  0xC0035FD6
 };
 if (instEqual(origCode_cache_getImp, 28, origFuncPtr)) {
  applyPatch(newCode_cache_getImp, 27, origFuncPtr);
 } else if (instEqual(newCode_cache_getImp, 27, origFuncPtr)) {
  printf("libobjc's cache_getImp has already been patched by iOptimize.\n");
 } else {
  printf("cache_getImp appears to be changed, iOptimize did not optimize\n");
 }

 /* objc_msgSendSuper2 patch */
 /* same as objc_msgSend patch, save mov instruction */
 origFuncPtr = dlsym(mainProgramHandle, "objc_msgSendSuper2");
 if (!origFuncPtr) {
  fprintf(stderr, "dlsym %s failed\n", dlerror());
  return;
 }
 instruction64 origCode_objc_msgSendSuper2[25] = {
  0x004040A9,
  0x100640F9,
  0xEF0310AA,
  0x0A0A40F9,
  0x4BFD70D3,
  0x4ABD4092,
  0x2C000B0A,
  0x4D110C8B,
  0xB125FFA8,
  0x3F0101EB,
  0x61000054,
  0x310210CA,
  0x20021FD6,
  0x690600B4,
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
  0x28000014
 }
 instruction64 newCode_objc_msgSendSuper2[25] = {
  0x003C40A9,
  0xEF0540F9,
  0xEA0940F9,
  0x4BFD70D3,
  0x4ABD4092,
  0x2C000B0A,
  0x4D110C8B,
  0xB125FFA8,
  0x3F0101EB,
  0x81000054,
  0xF0030FAA,
  0x310210CA,
  0x20021FD6,
  0x690600B4,
  0xBF010AEB,
  0x02FFFF54,
  0x4D512B8B,
  0x4C110C8B,
  0xB125FFA8,
  0x3F0101EB,
  0xC0FEFF54,
  0x3F0100F1,
  0xA0114CFA,
  0x68FFFF54,
  0x28000014
 }
 if (instEqual(origCode_objc_msgSendSuper2, 25, origFuncPtr)) {
  applyPatch(newCode_objc_msgSendSuper2, 25, origFuncPtr);
 } else if (instEqual(newCode_objc_msgSendSuper2, 25, origFuncPtr)) {
  printf("libobjc's objc_msgSendSuper2 has already been patched by iOptimize.\n");
 } else {
  printf("objc_msgSendSuper2 appears to be changed, iOptimize did not optimize\n");
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
