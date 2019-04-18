#include<stdio.h>
#include "malloc.h"
char heap[1024];
int main(int argc, char **argv){
	malloooc_init(heap, 1024);
	int *p=(int*)malloooc(10);
	printf("%p\n", p);
	char *w=(char*)malloooc(20);
	char *z=(char*)malloooc(20);
	printf("%p\n", w);
	memset(p, 'A', atoi(argv[1]));
	ooofree(p);
	ooofree(w);
	printf("Allocation and deallocation is done successfully!");
}
