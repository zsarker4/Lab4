#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define HEAP_SIZE 127
#define FREE_BLOCK 0
#define ALLOCATED_BLOCK 1

/*
hi! thanks for working with me!! <3

  things i still have left to do:
    - malloc function needs to be fixed (best fit algorithm - compaction)
    - blocklist function
    - test cases

  things i finished :) :
    - realloc operation
    - free operation
    - writemem operation
    - printmem operation
    - quit

*/

// memory heap w/ header for initial free block
uint8_t heap[HEAP_SIZE + 1] = {HEAP_SIZE << 1};

int find_free_block(int size) {
    int current_addr = 0;
    while (current_addr <= HEAP_SIZE) {
        uint8_t header = heap[current_addr];
        int block_size = (header >> 1) << 1;
        if ((header & 1) == FREE_BLOCK && block_size >= size) {
            return current_addr;
        }
        current_addr += block_size + 1;
    }
    return -1;
}
//this function returns malloc 10, malloc 5 output correctly but not malloc 2 (19 instead of 18)
int my_malloc(int size) {
    if (size <= 0 || size > HEAP_SIZE) {
        return -1; // Invalid size
    }
    // make sure size is even
    if (size % 2 != 0) {
        size++;
    }
    int current_addr = 0;
    while (current_addr <= HEAP_SIZE) {
        uint8_t header = heap[current_addr];
        int block_size = (header >> 1) << 1;
        if ((header & 1) == FREE_BLOCK && block_size >= size) {
            if (block_size > size) {
                // split the free block
                int split_addr = current_addr + size + 1;
                uint8_t split_header = ((block_size - size - 1) >> 1) << 1 | FREE_BLOCK;
                heap[split_addr] = split_header;
            }
            // Mark allocated block
            uint8_t header = (size >> 1) << 1 | ALLOCATED_BLOCK;
            heap[current_addr] = header;
            return current_addr + 1; // Return address ofpayload
        }
        current_addr += block_size + 1;
    }
    return -1; // no free blocks
}

int my_realloc(int ptr, int new_size) {
    if (ptr < 1 || ptr > HEAP_SIZE || new_size <= 0 || new_size > HEAP_SIZE) {
        return -1; // invalid pointer/size
    }
    ptr--; // adjust for payload address
    int current_size = ((heap[ptr] >> 1) << 1) - 1;
    if (new_size == current_size) {
        return ptr + 1;
    } else if (new_size < current_size) {
        // free excess memory
        heap[ptr] = ((new_size >> 1) << 1) | ALLOCATED_BLOCK;
        int split_addr = ptr + new_size + 1;
        uint8_t split_header = ((current_size - new_size - 1) >> 1) << 1 | FREE_BLOCK;
        heap[split_addr] = split_header;
        return ptr + 1;
    } else {
        // check if there is enough adjacent free space to expand
        int next_addr = ptr + current_size + 1;
        uint8_t next_header = heap[next_addr];
        int next_block_size = (next_header >> 1) << 1;
        while ((next_header & 1) == FREE_BLOCK && next_block_size > 0) {
            if (next_block_size >= new_size - current_size) {
                heap[ptr] = ((new_size >> 1) << 1) | ALLOCATED_BLOCK;
                int split_addr = ptr + new_size + 1;
                uint8_t split_header = ((next_block_size - (new_size - current_size) - 1) >> 1) << 1 | FREE_BLOCK;
                heap[split_addr] = split_header;
                return ptr + 1;
            }
            //move to  next free block
            ptr = next_addr;
            next_addr = ptr + next_block_size + 1;
            next_header = heap[next_addr];
            next_block_size = (next_header >> 1) << 1;
        }
        int new_block = my_malloc(new_size);
        if (new_block == -1) {
            return -1;
        }
        for (int i = 0; i < current_size; i++) {
            heap[new_block + i] = heap[ptr + i];
        }
        heap[ptr] = (current_size << 1) | FREE_BLOCK;
        return ptr + 1;
    }
}

// free allocated memory
void my_free(int ptr) {
    if (ptr < 1 || ptr > HEAP_SIZE) {
        return;
    }

    ptr--;
    if ((heap[ptr] & 1) == ALLOCATED_BLOCK) {
        heap[ptr] &= ~1; // discussion 6 slides
    }
}

void writemem(int ptr, char* data) {
    int len = strlen(data);
    for (int i = 0; i < len; i++) {
        heap[ptr + i] = data[i];
    }
}

void printmem(int ptr, int count) {
    printf("Memory Content:\n");
    for (int i = 0; i < count; i++) {
        printf("%02X ", heap[ptr + i]);
    }
    printf("\n");
}

// current state of the heap
void show_heap() {
    printf("Heap State:\n");
    int current_addr = 0;
    while (current_addr <= HEAP_SIZE) {
        uint8_t header = heap[current_addr];
        int block_size = (header >> 1) << 1;
        printf("%d-%d (%s)\n", current_addr, current_addr + block_size - 1, header & 1 ? "Allocated" : "Free");
        current_addr += block_size + 1;
    }
}

int main() {
    char command[32];
    int size, ptr, new_size;
    while (1) {
        printf(">");
        scanf("%s", command);
        if (strcmp(command, "malloc") == 0) {
            scanf("%d", &size);
            int result = my_malloc(size);
            if (result == -1) {
                printf("Allocation failed.\n");
            } else {
                printf("%d\n", result);
            }
        } else if (strcmp(command, "realloc") == 0) {
            scanf("%d", &ptr); // read first argument
            scanf("%d", &new_size); // read the second argument
            int result = my_realloc(ptr, new_size);
            if (result == -1) {
                printf("Reallocation failed.\n");
            } else {
                printf("%d\n", result);
            }
        } else if (strcmp(command, "free") == 0) {
            scanf("%d", &ptr);
            my_free(ptr);
        } else if (strcmp(command, "show") == 0) {
            show_heap();
        } else if (strcmp(command, "blocklist") == 0) {
            blocklist();
        } else if (strcmp(command, "writemem") == 0) {
            int ptr;
            char data[32];
            scanf("%d %s", &ptr, data);
            writemem(ptr, data);
        } else if (strcmp(command, "printmem") == 0) {
            int ptr, count;
            scanf("%d %d", &ptr, &count);
            printmem(ptr, count);
        } else if (strcmp(command, "quit") == 0) {
            break;
        } else {
            printf("Invalid command.\n");
        }
    }
    return 0;
}