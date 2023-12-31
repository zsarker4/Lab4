/*
Name:Zahradinee Sarker ID:24325057
Name:Kevin Tran ID:72244158 
*/

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define HEAP_SIZE 127
#define FREE_BLOCK 0
#define ALLOCATED_BLOCK 1

// memory heap w/ header for initial free block
uint8_t heap[HEAP_SIZE] = {HEAP_SIZE << 1};

// Find best fit free block
int find_free_block(int size) {
    int current_addr = 0;
    int best_fit_addr = -1;
    int best_fit_size = HEAP_SIZE + 1;
    while (current_addr < HEAP_SIZE) {
        uint8_t header = heap[current_addr];
        int block_size = (header >> 1);
        if ((header & 1) == FREE_BLOCK && block_size >= size) {
            // if there is a free block, check if it fits better
            if (block_size < best_fit_size) {
                best_fit_size = block_size;
                best_fit_addr = current_addr;
            }
        }
        current_addr += block_size;
    }
    return best_fit_addr; // no free block found
}
int my_malloc(int size) {
    if (size <= 0 || size > HEAP_SIZE - 1) {
        return -1; // Invalid size
    }
    // Find best fit free block
    int best_fit_addr = find_free_block(size + 1); 
    if (best_fit_addr != -1) {
        uint8_t header = heap[best_fit_addr];
        int block_size = header >> 1;
        if (block_size > size + 1) {
            // split the free block
            int split_addr = best_fit_addr + size + 1;
            heap[split_addr] = ((block_size - size - 1) << 1) | FREE_BLOCK;
        }
        // Mark allocated block
        heap[best_fit_addr] = (size + 1) << 1 | ALLOCATED_BLOCK;
        return best_fit_addr + 1;
    }
    return -1; // no free blocks
}

int my_realloc(int ptr, int new_size) {
    if (ptr < 1 || ptr > HEAP_SIZE || new_size <= 0 || new_size > HEAP_SIZE) {
        return -1; // invalid pointer/size
    }
    ptr--; // adjust for payload address
    int current_size = heap[ptr] >> 1;
    //printf("DEBUG: ptr = %d, new_size = %d, current_size = %d\n", ptr, new_size, current_size); // DEBUG
    if (new_size == current_size) {
        return ptr + 1;
    } else if (new_size < current_size) {
        // free excess memory
        heap[ptr] = ((new_size + 1) << 1) | ALLOCATED_BLOCK;
        int split_addr = ptr + new_size + 1;
        uint8_t split_header = ((current_size - new_size - 1) << 1) | FREE_BLOCK;
        heap[split_addr] = split_header;
        //printf("DEBUG: Free excess memory. split_addr = %d, split_size = %d\n", split_addr, split_header >> 1); // DEBUG
        return ptr + 1;
    } else {
        int current_addr = ptr + current_size;
        if (current_addr < HEAP_SIZE) {
            uint8_t header = heap[current_addr];
            int block_size = header >> 1;
            if ((header & 1) == FREE_BLOCK && block_size >= (new_size - current_size)) {
                heap[ptr] = (new_size << 1) | ALLOCATED_BLOCK;
                int split_addr = ptr + new_size;
                int split_size = current_size + block_size - new_size;
                if (split_size > 0) {
                    heap[split_addr] = (split_size << 1) | FREE_BLOCK;
                }
                //printf("DEBUG: Splitting. split_addr = %d, split_size = %d\n", split_addr, split_size); // DEBUG
                return ptr + 1;
            }
        }
        int new_block = my_malloc(new_size);
        if (new_block == -1) {
            return -1;
        }
        for (int i = 0; i < current_size; i++) {
            heap[new_block + i] = heap[ptr + i];
        }
        heap[ptr] = (current_size << 1) | FREE_BLOCK;
        //printf("DEBUG: Allocated new block. new_block = %d\n", new_block); // DEBUG
        return new_block;
    }
}

void my_free(int ptr) {
    if (ptr < 1 || ptr >= HEAP_SIZE) {
        return;
    }
    ptr--;
    // current block = free
    if ((heap[ptr] & 1) == ALLOCATED_BLOCK) {
        heap[ptr] &= ~1;
        int current_block_size = heap[ptr] >> 1;
        // check header of the next block
        int next_addr = ptr + current_block_size;
        if (next_addr < HEAP_SIZE)
        {
            uint8_t next_header = heap[next_addr];
            if ((next_header & 1) == FREE_BLOCK) {
                // if next block is free coalesce the two blocks
                int merged_size = current_block_size + (next_header >> 1);
                heap[ptr] = (merged_size << 1) | FREE_BLOCK;
            }
        }
    }
}

void writemem(int ptr, char* data) {
    int len = strlen(data);
    for (int i = 0; i < len; i++) {
        heap[ptr + i] = data[i];
    }
}

void printmem(int ptr, int count) {
    //printf("Memory Content:\n");
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

void blocklist() {
    // printf("Blocklist:\n");
    int current_addr = 0;
    while (current_addr < HEAP_SIZE) {
        uint8_t header = heap[current_addr];
        int block_size = header >> 1;
        printf("%d, %d, %s\n", current_addr + 1, block_size - 1, header & 1 ? "allocated" : "free");
        current_addr += block_size;
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
