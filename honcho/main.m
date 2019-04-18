//
//  main.m
//  honcho
//
//  Created by Jeff Crowell on 4/17/19.
//  Copyright © 2019 Jeff Crowell. All rights reserved.
//

#import <Foundation/Foundation.h>
#include <Hypervisor/hv.h>
#include <Hypervisor/hv_vmx.h>
#include <dirent.h>
#include <alloca.h>
#include <stdio.h>
#include <unistd.h>
#include <grp.h>
#include <pwd.h>
#include "shared_hypercalls.h"
#include "specialregs.h"

// defns

#define PS_LIMIT (0x200000)
#define KERNEL_STACK_SIZE (0x4000)
#define MAX_KERNEL_SIZE (PS_LIMIT - 0x5000 - KERNEL_STACK_SIZE)
#define MEM_SIZE (PS_LIMIT * 0x2)

// selector stuff
#define DESC_UNUSABLE 0x00010000
#define GSEL(s,r) (((s)<<3) | r)        /* a global selector */
#define SEG_NULL        0x0
#define SEG_CODE        0x1
#define SEG_DATA        0x2

// globals

hv_vcpuid_t vcpu;
uint8_t *vm_mem;


// functions
uint8_t *ReadFile(const char *name, ssize_t *fileLen);

int drop_privs(void) {
    char *user_name = "nobody";
    struct passwd *pwd;
    pwd = getpwnam(user_name);
    if(!pwd) { fprintf(stderr, "Can't find user `%s'\n", user_name); return 1; }
    if(0) printf("uid = %i, gid = %i\n", pwd->pw_uid, pwd->pw_gid);
    if(setgroups(0, 0) < 0) { perror("setgroups"); return 1; }
    if(setgid(pwd->pw_gid) < 0) { perror("setgid"); return 1; }
    if(setuid(pwd->pw_uid) < 0) { perror("setuid"); return 1; }
    if (seteuid(getuid()) != 0) {
        printf("COULDNT DROP PRIVS OMG!\n");
        exit(1);
    }
    return 0;
}

void vmm_create_vcpu(void) {
    hv_return_t ret;
    ret = hv_vcpu_create(&vcpu, HV_VCPU_DEFAULT);
    if (ret != HV_SUCCESS) {
        printf("WEW COULDNT CREATE VCPU");
    }
}

void vmm_create(void) {
    hv_return_t ret;
    ret = hv_vm_create(HV_VM_DEFAULT);
    if (ret != HV_SUCCESS) {
        printf("COULDNT CREATE VM SHIT!\n");
        exit(1);
    }
    // now set up the cpu
    vmm_create_vcpu();
}

void init_vmcs() {
    uint64_t vmx_cap_pinbased, vmx_cap_procbased, vmx_cap_procbased2, vmx_cap_entry, vmx_cap_exit;
    
    hv_vmx_read_capability(HV_VMX_CAP_PINBASED, &vmx_cap_pinbased);
    hv_vmx_read_capability(HV_VMX_CAP_PROCBASED, &vmx_cap_procbased);
    hv_vmx_read_capability(HV_VMX_CAP_PROCBASED2, &vmx_cap_procbased2);
    hv_vmx_read_capability(HV_VMX_CAP_ENTRY, &vmx_cap_entry);
    hv_vmx_read_capability(HV_VMX_CAP_EXIT, &vmx_cap_exit);
    
    /* set up vmcs misc */
    
#define cap2ctrl(cap,ctrl) (((ctrl) | ((cap) & 0xffffffff)) & ((cap) >> 32))
    
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_CTRL_PIN_BASED, cap2ctrl(vmx_cap_pinbased, 0));
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_CTRL_CPU_BASED, cap2ctrl(vmx_cap_procbased,
                                                 CPU_BASED_HLT |
                                                 CPU_BASED_CR8_LOAD |
                                                 CPU_BASED_CR8_STORE));
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_CTRL_CPU_BASED2, cap2ctrl(vmx_cap_procbased2, 0));
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_CTRL_VMENTRY_CONTROLS,  cap2ctrl(vmx_cap_entry,
                                                         VMENTRY_LOAD_EFER |
                                                         VMENTRY_GUEST_IA32E));
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_CTRL_VMEXIT_CONTROLS, cap2ctrl(vmx_cap_exit, VMEXIT_LOAD_EFER));
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_CTRL_EXC_BITMAP, 0xffffffff);
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_CTRL_CR0_SHADOW, 0);
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_CTRL_CR4_MASK, 0);
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_CTRL_CR4_SHADOW, 0);
}

void init_msr() {
    hv_vcpu_enable_native_msr(vcpu, MSR_TIME_STAMP_COUNTER, 1);
    hv_vcpu_enable_native_msr(vcpu, MSR_TSC_AUX, 1);
    hv_vcpu_enable_native_msr(vcpu, MSR_KERNEL_GS_BASE, 1);
}

void map_memory() {
    vm_mem = valloc(MEM_SIZE);
    bzero(vm_mem, MEM_SIZE);
    hv_vm_map(vm_mem, 0, MEM_SIZE, HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC);
}

void init_page() {
    /*
    uint64_t pml4_addr = MAX_KERNEL_SIZE;
    uint64_t *pml4 = (void *)(vm_mem + pml4_addr);
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_CR0, CR0_PG | CR0_PE | CR0_NE);
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_CR3, (uint64_t)pml4);
    */
    
    uint64_t pml4_addr = 0x10000;
    uint64_t *pml4 = (void *)(vm_mem + pml4_addr);
    
    uint64_t pdpt_addr = 0x20000;
    uint64_t *pdpt = (void *)(vm_mem + pdpt_addr);
    
    uint64_t pd_addr = 0x30000;
    uint64_t *pd = (void *)(vm_mem + pd_addr);
    
    pml4[0] = 3 | pdpt_addr; // PDE64_PRESENT | PDE64_RW | pdpt_addr
    pdpt[0] = 3 | pd_addr; // PDE64_PRESENT | PDE64_RW | pd_addr
    pd[0] = 3 | 0x80; // PDE64_PRESENT | PDE64_RW | PDE64_PS
    
    //sregs->cr3 = pml4_addr;
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_CR3, (uint64_t)pml4_addr);

    //sregs->cr4 = 1 << 5; // CR4_PAE;
    //sregs->cr4 |= 0x600; // CR4_OSFXSR | CR4_OSXMMEXCPT; /* enable SSE instruction */
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_CR4, (uint64_t)(1 << 5) | 0x600);

    //sregs->cr0 = 0x80050033; // CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_WP | CR0_AM | CR0_PG
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_CR0, 0x80050033);

    //sregs->efer = 0x500; // EFER_LME | EFER_LMA
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_IA32_EFER, 0x500);

}

void init_special_regs() {
    uint64_t cr0;
    hv_vmx_vcpu_read_vmcs(vcpu, VMCS_GUEST_CR0, &cr0);
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_CR0, (cr0 & ~CR0_EM) | CR0_MP);
    
    uint64_t cr4;
    hv_vmx_vcpu_read_vmcs(vcpu, VMCS_GUEST_CR4, &cr4);
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_CR4, cr4 | CR4_PAE | CR4_OSFXSR | CR4_OSXMMEXCPT | CR4_VMXE | CR4_OSXSAVE);
    
    uint64_t efer;
    hv_vmx_vcpu_read_vmcs(vcpu, VMCS_GUEST_IA32_EFER, &efer);
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_IA32_EFER, efer | EFER_LME | EFER_LMA);
}

void init_segment() {
    /*
    kmap(gdt, 0x1000, HV_MEMORY_READ | HV_MEMORY_WRITE);
    
    vmm_write_vmcs(VMCS_GUEST_GDTR_BASE, gdt_ptr);
    vmm_write_vmcs(VMCS_GUEST_GDTR_LIMIT, 3 * 8 - 1);
     */
    
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_TR_BASE, 0);
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_TR_LIMIT, 0);
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_TR_AR, 0x0000008b);
    
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_LDTR_BASE, 0);
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_LDTR_LIMIT, 0);
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_LDTR_AR, DESC_UNUSABLE);
    
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_IDTR_BASE, 0);
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_IDTR_LIMIT, 0xffff);
    
    uint32_t codeseg_ar = 0x0000209B;
    uint32_t dataseg_ar = 0x00000093;
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_CS_BASE, 0);
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_CS_LIMIT, 0);
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_CS_AR, codeseg_ar);
    
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_DS_BASE, 0);
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_DS_LIMIT, 0);
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_DS_AR, dataseg_ar);
    
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_ES, 0);
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_ES_BASE, 0);
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_ES_LIMIT, 0);
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_ES_AR, dataseg_ar);
    
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_FS, 0);
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_FS_BASE, 0);
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_FS_LIMIT, 0);
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_FS_AR, dataseg_ar);
    
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_GS, 0);
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_GS_BASE, 0);
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_GS_LIMIT, 0);
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_GS_AR, dataseg_ar);
    
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_SS, 0);
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_SS_BASE, 0);
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_SS_LIMIT, 0);
    hv_vmx_vcpu_write_vmcs(vcpu, VMCS_GUEST_SS_AR, dataseg_ar);
    
    
    hv_vcpu_write_register(vcpu, HV_X86_CS, GSEL(SEG_CODE, 0));
    hv_vcpu_write_register(vcpu, HV_X86_DS, GSEL(SEG_DATA, 0));
    hv_vcpu_write_register(vcpu, HV_X86_ES, GSEL(SEG_DATA, 0));
    hv_vcpu_write_register(vcpu, HV_X86_FS, GSEL(SEG_DATA, 0));
    hv_vcpu_write_register(vcpu, HV_X86_GS, GSEL(SEG_DATA, 0));
    hv_vcpu_write_register(vcpu, HV_X86_SS, GSEL(SEG_DATA, 0));
    hv_vcpu_write_register(vcpu, HV_X86_TR, 0);
    hv_vcpu_write_register(vcpu, HV_X86_LDTR, 0);
}

uint64_t hypervise(uint8_t *code, size_t codesz) {
    hv_vcpu_write_register(vcpu, HV_X86_RIP, 0);
    hv_vcpu_write_register(vcpu, HV_X86_RFLAGS, 0x2);
    hv_vcpu_write_register(vcpu, HV_X86_RAX, 0);
    memcpy(vm_mem, code, codesz);
    uint8_t cont = 1;
    hv_vcpu_write_register(vcpu, HV_X86_RSP, MAX_KERNEL_SIZE + KERNEL_STACK_SIZE);
    hv_vcpu_write_register(vcpu, HV_X86_RDI, PS_LIMIT);
    hv_vcpu_write_register(vcpu, HV_X86_RSI, MEM_SIZE - PS_LIMIT); /* total length of free pages */
    
    for (;;) {
        hv_vmx_vcpu_write_vmcs(vcpu, VMCS_RO_EXIT_REASON, 0);
        uint64_t rip, rax;
        hv_vcpu_read_register(vcpu, HV_X86_RIP, &rip);
        hv_vcpu_read_register(vcpu, HV_X86_RAX, &rax);
        
        //printf("RIP : 0x%llx\n", rip);
        
        hv_vcpu_run(vcpu);
        
        uint64_t exit_reason;
        hv_vmx_vcpu_read_vmcs(vcpu, VMCS_RO_EXIT_REASON, &exit_reason);
        switch (exit_reason) {
            case VMX_REASON_IRQ: {
                uint64_t soft_irq;
                hv_vmx_vcpu_read_vmcs(vcpu, IRQ_INFO_SOFT_IRQ, &soft_irq);
                //NSLog(@"Dispatch VM Exit: %x", soft_irq);
                break;
            }
            case VMX_REASON_HLT:
                //NSLog(@"Dispatch VM Exit: HLT");
                cont = 0;
                break;
            case VMX_REASON_EPT_VIOLATION:
            {
                //NSLog(@"Dispatch VM Exit: EPT_VIOLATION");
                // lol idk
                //cont = 0;
                break;
            }
            case VMX_REASON_TRIPLE_FAULT:
                //NSLog(@"Dispatch VM Exit: TRIPLE_FAULT");
                cont = 0;
                break;
            case VMX_REASON_IO:
            {
                uint64_t rax, rdi, rsi;
                hv_vcpu_read_register(vcpu, HV_X86_RIP, &rip);
                hv_vcpu_read_register(vcpu, HV_X86_RAX, &rax);
                hv_vcpu_read_register(vcpu, HV_X86_RDI, &rdi);
                hv_vcpu_read_register(vcpu, HV_X86_RSI, &rsi);

                switch(rdi) {
                    case HYPERCALL_PUTCHAR:
                    {
                        printf("%c", (uint8_t)rax);
                        break;
                    }
                    case HYPERCALL_PUTSTR:
                    {
                        char *bufptr = &vm_mem[rax];
                        printf("%s\n", bufptr);
                        break;
                    }
                    case HYPERCALL_PUTQWORD:
                    {
                        printf("%p\n", rax);
                        break;
                    }
                    case HYPERCALL_READSTR:
                    {
                        size_t len = rsi;
                        char *bufptr = &vm_mem[rax];
                        ssize_t ret = read(0, bufptr, len);
                        hv_vcpu_write_register(vcpu, HV_X86_RAX, ret);
                        break;
                    }
                    case HYPERCALL_GETDIRLIST:
                    {
                        struct dirent *de;
                        DIR *dr = opendir(".");
                        if (dr == NULL)  {// opendir returns NULL if couldn't open directory
                            printf("Could not open current directory" );
                            break;
                        }
                        while ((de = readdir(dr)) != NULL) {
                            printf("%s\n", de->d_name);
                        }
                        closedir(dr);
                        break;
                    }
                    case HYPERCALL_CATFILE:
                    {
                        char *bufptr = &vm_mem[rax];
                        if (strcasestr(bufptr, "flag")) {
                            printf("hypervisor blocked read of %s\n", bufptr);
                            break;
                        }
                        ssize_t fileLen;
                        uint8_t *file = ReadFile(bufptr, &fileLen);
                        write(1, file, fileLen);
                        break;
                    }
                    default:
                    {
                        printf("\nunsupported hypercall at %p\n", rip);
                        cont = 0;
                        break;
                    }
                }

                uint64_t inst_length;
                hv_vmx_vcpu_read_vmcs(vcpu, VMCS_RO_VMEXIT_INSTR_LEN, &inst_length);
                size_t next_rip = rip + inst_length;
                hv_vcpu_write_register(vcpu, HV_X86_RIP, next_rip);
                //NSLog(@"Dispatch VM Exit: IO");
                break;
            }
            case VMX_REASON_VMENTRY_GUEST:
                //NSLog(@"Dispatch VM Exit: VMENTRY_GUEST");
                break;
            case VMX_REASON_VMENTRY_MSR:
                //NSLog(@"Dispatch VM Exit: VMENTRY_MSR");
                break;
            case VMX_REASON_VMX_TIMER_EXPIRED:
                // DEBUG("Dispatch VM Exit: " << "TIMER EXPIRED");
                break;
            case VMX_REASON_EXC_NMI:
            {
                //hvf_debug_print_nmi(intr_info);
                cont = 0;
                break;
            }
            case VMX_REASON_WRMSR:
            {
                NSLog(@"Dispatch VM WRMSR Exit: %llx", exit_reason);
                uint64_t inst_length;
                hv_vmx_vcpu_read_vmcs(vcpu, VMCS_RO_VMEXIT_INSTR_LEN, &inst_length);
                size_t next_rip = rip + inst_length;
                hv_vcpu_write_register(vcpu, HV_X86_RIP, next_rip);
                cont = 1;
                break;
            }
            default:
            {
                NSLog(@"Dispatch VM Exit: %llx", exit_reason);
                cont = 1;
                break;
            }
                
        }
        
        if (cont) {
            continue;
        }
        return 0;
    }
    return 0;
}

uint8_t *ReadFile(const char *name, ssize_t *fileLen) {
    FILE *file;
    uint8_t *buffer;
    
    //Open file
    file = fopen(name, "rb");
    if (!file)
    {
        fprintf(stderr, "Unable to open file %s", name);
        return NULL;
    }
    
    //Get file length
    fseek(file, 0, SEEK_END);
    *fileLen=ftell(file);
    fseek(file, 0, SEEK_SET);
    
    //Allocate memory
    buffer=(uint8_t  *)malloc(*fileLen+1);
    if (!buffer) {
        fprintf(stderr, "Memory error!");
        fclose(file);
        return NULL;
    }
    
    //Read file contents into buffer
    fread(buffer, *fileLen, 1, file);
    fclose(file);

    return buffer;
}

int main(int argc, const char * argv[]) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    @autoreleasepool {
        // insert code here...
        NSLog(@"hi there");
        NSLog(@"dropping privs");
        if(drop_privs()) {
            printf("SHIT!\n");
            exit(0);
        }
        NSLog(@"initializing vcpu");
        vmm_create();
        NSLog(@"mapping memory to the guest");
        map_memory();
        NSLog(@"initializing vmcs");
        init_vmcs();
        NSLog(@"initializing msrs");
        init_msr();
        NSLog(@"initializing pages, long ass mode");
        init_page();
        NSLog(@"initializing special registers");
        init_special_regs();
        NSLog(@"initializing segment");
        init_segment();
        ssize_t code_len = 0;
        uint8_t *code = ReadFile(argv[1], &code_len);
        //uint8_t code[] = "H\xB8\x41\x42\x43\x44\x31\x32\x33\nj\bY\xBA\x17\x02\x00\x00\xEEH\xC1\xE8\b\xE2\xF9\xF4";
        NSLog(@"let's go!");
        alarm(atoi(argv[2]));
        hypervise(code, code_len);
    }
    return 0;
}
