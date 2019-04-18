#ifndef __MALLOOOC
#define __MALLOOOC
#include<stddef.h>
void malloooc_init(void *ptr, size_t size);
void *malloooc(size_t noOfBytes);
void merge();
void ooofree(void* ptr);
#endif
