#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <mach/mach.h>
#include <mach-o/arch.h>

struct RemoteProcess {
    pid_t pid;
    mach_port_t task;
    void *fooAddr;
    void *dataAddr;
};

bool attach(RemoteProcess &proc) {
    FILE *file = fopen("data.txt", "r");
    if (!file) {
        fprintf(stderr, "Failed to open data.txt\n");
        return false;
    }
    fscanf(file, "%d", &proc.pid);
    fscanf(file, "%p", &proc.fooAddr);
    fscanf(file, "%p", &proc.dataAddr);
    fclose(file);

    kern_return_t kr;
    kr = task_for_pid(mach_task_self(), proc.pid, &proc.task);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Failed to get task for pid %d: %s\n", proc.pid, mach_error_string(kr));
        return false;
    }
    printf("Attached to pid %d\n", proc.pid);

    return true;
}

bool suspend(RemoteProcess &proc) {
    kern_return_t kr = task_suspend(proc.task);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Failed to suspend task for pid %d: %s\n", proc.pid, mach_error_string(kr));
        return false;
    }
    printf("Task for pid %d suspended\n", proc.pid);
    return true;
}

bool resume(RemoteProcess &proc) {
    kern_return_t kr = task_resume(proc.task);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Failed to resume task for pid %d: %s\n", proc.pid, mach_error_string(kr));
        return false;
    }
    printf("Task for pid %d resumed\n", proc.pid);
    return true;
}

bool writeBytes(RemoteProcess &proc, void *remoteAddress, void *data, size_t numBytes) {
    kern_return_t kr = vm_write(proc.task, (vm_address_t)remoteAddress, (vm_offset_t)data, numBytes);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Failed to write to memory: %s\n", mach_error_string(kr));
        return false;
    }
    printf("Wrote %zu bytes to address %p\n", numBytes, remoteAddress);
    return true;
}

bool readBytes(RemoteProcess &proc, void *remoteAddress, void *data, size_t numBytes) {
    vm_size_t outSize;
    kern_return_t kr = vm_read_overwrite(proc.task, (vm_address_t)remoteAddress, numBytes, (vm_address_t)data, &outSize);
    if (kr != KERN_SUCCESS || outSize != numBytes) {
        fprintf(stderr, "Failed to read from memory: %s\n", mach_error_string(kr));
        return false;
    }
    printf("Read %zu bytes from address %p\n", numBytes, remoteAddress);
    return true;
}

bool allocate(RemoteProcess &proc, size_t size, void **remoteAddress) {
    vm_address_t address;
    kern_return_t kr = vm_allocate(proc.task, &address, size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Failed to allocate memory in remote process: %s\n", mach_error_string(kr));
        return false;
    }
    *remoteAddress = (void*)address;
    printf("Allocated %zu bytes at address %p in remote process\n", size, (void*)remoteAddress);
    return true;
}

bool changeProtection(RemoteProcess &proc, void *address, size_t size, vm_prot_t newProtection) {
    kern_return_t kr = vm_protect(proc.task, (vm_address_t)address, size, false, newProtection);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Failed to change memory protection: %s\n", mach_error_string(kr));
        return false;
    }
    printf("Changed projection of address %p, size %zu to %d\n", address, size, newProtection);
    return true;
}

bool trampoline(RemoteProcess &proc, void *oldFunction, void *newFunction) {
    const NXArchInfo *archInfo = NXGetLocalArchInfo();
    if (archInfo == nullptr) {
        fprintf(stderr, "Failed to get local architecture info\n");
        return false;
    }

    vm_prot_t oldProtection;
    size_t jumpInstructionSize;

    if (strcmp(archInfo->name, "x86_64") == 0) {
        int64_t offset = (int64_t)newFunction - ((int64_t)oldFunction + 5);
        if (offset >= INT32_MIN && offset <= INT32_MAX) {
            unsigned char jumpInstruction[5];
            jumpInstruction[0] = 0xE9; // JMP rel32
            *(int32_t *)(jumpInstruction + 1) = (int32_t)offset;

            jumpInstructionSize = sizeof(jumpInstruction);

            if (!changeProtection(proc, oldFunction, jumpInstructionSize, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY)) {
                return false;
            }

            if (!writeBytes(proc, oldFunction, jumpInstruction, jumpInstructionSize)) {
                return false;
            }

            if (!changeProtection(proc, oldFunction, jumpInstructionSize, VM_PROT_READ | VM_PROT_EXECUTE)) {
                return false;
            }
        } else {
            fprintf(stderr, "Offset too large for short jump: %lld\n", offset);
            return false;
        }
    } else if (strcmp(archInfo->name, "arm64") == 0 || strcmp(archInfo->name, "arm64e") == 0) {
        int64_t offset = (int64_t)newFunction - (int64_t)oldFunction;
        if (offset >= INT32_MIN && offset <= INT32_MAX) {
            int32_t b_offset = offset / 4;
            unsigned char jumpInstruction[4];
            jumpInstruction[0] = (b_offset & 0xFF);
            jumpInstruction[1] = (b_offset >> 8) & 0xFF;
            jumpInstruction[2] = (b_offset >> 16) & 0xFF;
            jumpInstruction[3] = 0x14 | ((b_offset >> 24) & 0x3);

            jumpInstructionSize = sizeof(jumpInstruction);

            if (!changeProtection(proc, oldFunction, jumpInstructionSize, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY)) {
                return false;
            }

            if (!writeBytes(proc, oldFunction, jumpInstruction, jumpInstructionSize)) {
                return false;
            }

            if (!changeProtection(proc, oldFunction, jumpInstructionSize, VM_PROT_READ | VM_PROT_EXECUTE)) {
                return false;
            }
        } else {
            fprintf(stderr, "Offset too large for short jump: %lld\n", offset);
            return false;
        }
    } else {
        fprintf(stderr, "Unsupported architecture: %s\n", archInfo->name);
        return false;
    }

    printf("Patched function at %p to jump to %p\n", (void*)oldFunction, (void*)newFunction);
    return true;
}


int bar() {
    return 857;
}
void barEnd() {}

int main(int argc, char** argv) {
    RemoteProcess proc;
    attach(proc);
    suspend(proc);

    int oldValue = 0;
    readBytes(proc, proc.dataAddr, &oldValue, sizeof(oldValue));
    printf("Old value: %d\n", oldValue);

    int newValue = 456;
    writeBytes(proc, proc.dataAddr, &newValue, sizeof(newValue));
    resume(proc);

    sleep(4);

    suspend(proc);
    int barSize = (char*)barEnd - (char*)bar;
    printf("Bar size: %d\n", barSize);
    void *remoteBar;
    allocate(proc, barSize, &remoteBar);
    writeBytes(proc, remoteBar, (void*)bar, barSize);
    changeProtection(proc, remoteBar, barSize, VM_PROT_READ | VM_PROT_EXECUTE);
    trampoline(proc, proc.fooAddr, remoteBar);

    resume(proc);
    return 0;
}