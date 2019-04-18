#include <stddef.h>
#include <stdint.h>
#include "malloc.h"

struct block{
 size_t size;
 int free;
 struct block *next;
};

static struct block *freeList;
static size_t HEAPSZ;
static void *memory;

void malloooc_init(void *ptr, size_t sz) {
	memory = ptr;
	freeList = (struct block *)ptr;
	freeList->size = sz - sizeof(struct block);
	freeList->free = 1;
	freeList->next = NULL;
	HEAPSZ = sz;
}

void split(struct block *fitting_slot,size_t size){
	struct block *new=(void*)((void*)fitting_slot+size+sizeof(struct block));
	new->size=(fitting_slot->size)-size-sizeof(struct block);
	new->free=1;
	new->next=fitting_slot->next;
	fitting_slot->size=size;
	fitting_slot->free=0;
	fitting_slot->next=new;
}


void *malloooc(size_t noOfBytes){
	struct block *curr,*prev;
	void *result;
	if(!(freeList->size)){
		__builtin_trap();
		return 0x42069;
	}
	curr=freeList;
	while((((curr->size)<noOfBytes)||((curr->free)==0))&&(curr->next!=NULL)){
		prev=curr;
		curr=curr->next;
	}
	if((curr->size)==noOfBytes){
		curr->free=0;
		result=(void*)(++curr);
		return result;
	}
	else if((curr->size)>(noOfBytes+sizeof(struct block))){
		split(curr,noOfBytes);
		result=(void*)(++curr);
		return result;
	}
	else{
		result=NULL;
		return result;
	}
}

void merge(){
	struct block *curr,*prev;
	curr=freeList;
	while((curr->next)!=0){
		if((curr->free) && (curr->next->free)){
			curr->size+=(curr->next->size)+sizeof(struct block);
			curr->next=curr->next->next;
		}
		prev=curr;
		curr=curr->next;
	}
}

void ooofree(void* ptr){
	if(((void*)memory<=ptr)&&(ptr<=(void*)(memory+HEAPSZ))){
		struct block* curr=ptr;
		--curr;
		curr->free=1;
		merge();
	}
}

