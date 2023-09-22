#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>

__attribute__((constructor)) static void init() {
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
 /* now, modify code... (currently using ez method, improve this later to save 1 cycle/instruction via nop-less method */
 unsigned long long originalCbzInstruction = 0x400000B4; /* cbz x0, loc_3fb0 */
 uintptr_t ptrToInst = (uintptr_t)origFuncPtr;
 /* TODO: Add safety check here so if we can't find the instruction, this won't loop infinitely. */
 while (*ptrToInst != originalCbzInstruction) {
  ptrToInst++;
 }
 *ptrToInst = 0x409F08B5; /* cbnz x0, __class_getVariable */
 ptrToInst++;
 *ptrToInst = 0x1F2003D5; /* nop */
}
