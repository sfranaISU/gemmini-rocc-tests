/*
#include <assert.h>
#include <malloc.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include "include/accellib.h"

#define PAGESIZE_BYTES 4096

unsigned char * Aes256AccelSetup(size_t write_region_size) {
#ifndef NOACCEL_DEBUG
    ROCC_INSTRUCTION(AES256_OPCODE, FUNCT_SFENCE);
#endif

    size_t regionsize = sizeof(char) * (write_region_size);

    unsigned char* fixed_alloc_region = (unsigned char*)memalign(PAGESIZE_BYTES, regionsize);
    for (uint64_t i = 0; i < regionsize; i += PAGESIZE_BYTES) {
        fixed_alloc_region[i] = 0;
    }

    uint64_t fixed_ptr_as_int = (uint64_t)fixed_alloc_region;

    assert((fixed_ptr_as_int & 0x7) == 0x0);

    printf("constructed %" PRIu64 " byte region, starting at 0x%016" PRIx64 ", paged-in, for accel\n",
            (uint64_t)regionsize, fixed_ptr_as_int);

    return fixed_alloc_region;
}

volatile int Aes256BlockOnCompletion(volatile int * completion_flag) {
    uint64_t retval;
#ifndef NOACCEL_DEBUG
    ROCC_INSTRUCTION_D(AES256_OPCODE, retval, FUNCT_CHECK_COMPLETION);
#endif
    asm volatile ("fence");

#ifndef NOACCEL_DEBUG
    while (! *(completion_flag)) {
        asm volatile ("fence");
    }
#endif
    return *completion_flag;
}

void Aes256AccelNonblocking(bool encrypt,
                            const unsigned char* data,
                            size_t data_length,
                            uint64_t key0,
                            uint64_t key1,
                            uint64_t key2,
                            uint64_t key3,
                            unsigned char* result,
                            int* success_flag) {
    assert (data_length % 16 == 0 && "Data length must be divisible by block size of 128b (16B)");
#ifndef NOACCEL_DEBUG
    ROCC_INSTRUCTION_SS(AES256_OPCODE,
                        (uint64_t)data,
                        (uint64_t)data_length,
                        FUNCT_SRC_INFO);

    ROCC_INSTRUCTION_SS(AES256_OPCODE,
                        (uint64_t)key0,
                        (uint64_t)key1,
                        FUNCT_KEY_0);

    ROCC_INSTRUCTION_SS(AES256_OPCODE,
                        (uint64_t)key2,
                        (uint64_t)key3,
                        FUNCT_KEY_1);

    ROCC_INSTRUCTION_S(AES256_OPCODE,
                        (uint64_t)encrypt,
                        FUNCT_MODE);

    ROCC_INSTRUCTION_SS(AES256_OPCODE,
                        (uint64_t)result,
                        (uint64_t)success_flag,
                        FUNCT_DEST_INFO);
#endif
}

int Aes256Accel(bool encrypt,
                const unsigned char* data,
                size_t data_length,
                uint64_t key0,
                uint64_t key1,
                uint64_t key2,
                uint64_t key3,
                unsigned char* result) {
    int completion_flag = 0;

#ifdef NOACCEL_DEBUG
    printf("completion_flag addr : 0x%x\n", &completion_flag);
#endif

    Aes256AccelNonblocking(encrypt,
                            data,
                            data_length,
                            key0,
                            key1,
                            key2,
                            key3,
                            result,
                            &completion_flag);
    return Aes256BlockOnCompletion(&completion_flag);
}

*/

// #include <stddef.h>
// #include <stdlib.h>
// #include <stdbool.h>
// #include <stdio.h>
// #include <stdint.h>
// #include <inttypes.h>
// //#include "include/accellib.h"

// //#include "include/accellib.h"
// //#include "include/AES_encoding.h"

// #ifndef BAREMETAL
// #include <sys/mman.h>
// #endif


// #define AES_BLOCK_BYTES 16
// #define MAX_BLOCKS 4
// #define DATA_LEN (AES_BLOCK_BYTES * MAX_BLOCKS)

// // Aligned static buffers
// static unsigned char input_data[DATA_LEN] __attribute__((aligned(64)));
// static unsigned char ciphertext[DATA_LEN] __attribute__((aligned(64)));
// static unsigned char decrypted[DATA_LEN] __attribute__((aligned(64)));

// // Dummy rdcycle
// static inline uint64_t rdcycle() {
//     uint64_t cycle;
//     asm volatile ("rdcycle %0" : "=r"(cycle));
//     return cycle;
// }

// // Stub assert for baremetal
// #define assert(x) if (!(x)) while (1)

// extern int Aes256Accel(bool encrypt,
//                        const unsigned char* data,
//                        size_t data_length,
//                        uint64_t key0,
//                        uint64_t key1,
//                        uint64_t key2,
//                        uint64_t key3,
//                        unsigned char* result);

// int main() {
// #ifndef BAREMETAL
//     if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0) {
//       perror("mlockall failed");
//       exit(1);
//     }
// #endif

//     for (size_t i = 0; i < DATA_LEN; ++i) input_data[i] = i;

//     uint64_t key[4] = { 0x0, 0x1, 0x2, 0x3 };

//     uint64_t start = rdcycle();
//     Aes256Accel(true, input_data, DATA_LEN, key[0], key[1], key[2], key[3], ciphertext);
//     uint64_t end = rdcycle();

//     printf("Encryption cycles: %lu\n", end - start);

//     Aes256Accel(false, ciphertext, DATA_LEN, key[0], key[1], key[2], key[3], decrypted);

//     // Compare results
//     for (size_t i = 0; i < DATA_LEN; i++) {
//         if (input_data[i] != decrypted[i]) {
//             printf("Mismatch at %lu: %x != %x\n", i, input_data[i], decrypted[i]);
//             printf("TEST FAILED\n");
//             return 1;
//         }
//     }

//     printf("TEST PASSED\n");
//     return 0;
// }
// AES_test.c

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <assert.h>
#include <stdlib.h>

#ifndef BAREMETAL
#include <sys/mman.h>
#endif
#include "include/gemmini_testutils.h"


#define AES256_OPCODE 1
#define FUNCT_SFENCE 0
#define FUNCT_SRC_INFO 1
#define FUNCT_DEST_INFO 2
#define FUNCT_CHECK_COMPLETION 3
#define FUNCT_MODE 4
#define FUNCT_KEY_0 5
#define FUNCT_KEY_1 6

// ========================== RoCC Macros ==========================
#ifndef SRC_MAIN_C_ROCC_H
#define SRC_MAIN_C_ROCC_H

#define ROCC_INSTRUCTION_DSS(X, rd, rs1, rs2, funct) \
    ROCC_INSTRUCTION_R_R_R(X, rd, rs1, rs2, funct)

#define ROCC_INSTRUCTION_DS(X, rd, rs1, funct) \
    ROCC_INSTRUCTION_R_R_I(X, rd, rs1, 0, funct)

#define ROCC_INSTRUCTION_D(X, rd, funct) \
    ROCC_INSTRUCTION_R_I_I(X, rd, 0, 0, funct)

#define ROCC_INSTRUCTION_SS(X, rs1, rs2, funct) \
    ROCC_INSTRUCTION_I_R_R(X, 0, rs1, rs2, funct)

#define ROCC_INSTRUCTION_S(X, rs1, funct) \
    ROCC_INSTRUCTION_I_R_I(X, 0, rs1, 0, funct)

#define ROCC_INSTRUCTION(X, funct) \
    ROCC_INSTRUCTION_I_I_I(X, 0, 0, 0, funct)

#define ROCC_XD     0x4
#define ROCC_XS1    0x2
#define ROCC_XS2    0x1

#define ROCC_INSTRUCTION_R_R_R(X, rd, rs1, rs2, funct) \
    __asm__ __volatile__ ( \
        ".insn r CUSTOM_" #X ", %3, %4, %0, %1, %2\n\t" \
        : "=r" (rd) \
        : "r" (rs1), "r" (rs2), \
          "i" (ROCC_XD | ROCC_XS1 | ROCC_XS2), "i" (funct))

#define ROCC_INSTRUCTION_R_R_I(X, rd, rs1, rs2, funct) \
    __asm__ __volatile__ ( \
        ".insn r CUSTOM_" #X ", %3, %4, %0, %1, x%2\n\t" \
        : "=r" (rd) \
        : "r" (rs1), "K" (rs2), \
          "i" (ROCC_XD | ROCC_XS1), "i" (funct))

#define ROCC_INSTRUCTION_R_I_I(X, rd, rs1, rs2, funct) \
    __asm__ __volatile__ ( \
        ".insn r CUSTOM_" #X ", %3, %4, %0, x%1, x%2\n\t" \
        : "=r" (rd) \
        : "K" (rs1), "K" (rs2), \
          "i" (ROCC_XD), "i" (funct))

#define ROCC_INSTRUCTION_I_R_R(X, rd, rs1, rs2, funct) \
    __asm__ __volatile__ ( \
        ".insn r CUSTOM_" #X ", %3, %4, x%0, %1, %2\n\t" \
        : \
        : "K" (rd), "r" (rs1), "r" (rs2), \
          "i" (ROCC_XS1 | ROCC_XS2), "i" (funct))

#define ROCC_INSTRUCTION_I_R_I(X, rd, rs1, rs2, funct) \
    __asm__ __volatile__ ( \
        ".insn r CUSTOM_" #X ", %3, %4, x%0, %1, x%2\n\t" \
        : \
        : "K" (rd), "r" (rs1), "K" (rs2), \
          "i" (ROCC_XS1), "i" (funct))

#define ROCC_INSTRUCTION_I_I_I(X, rd, rs1, rs2, funct) \
    __asm__ __volatile__ ( \
        ".insn r CUSTOM_" #X ", %3, %4, x%0, x%1, x%2\n\t" \
        : \
        : "K" (rd), "K" (rs1), "K" (rs2), \
          "i" (0), "i" (funct))

#endif // SRC_MAIN_C_ROCC_H

// ========================== Baremetal Stubs ==========================
//#define assert(x) if (!(x)) while (1)

static inline uint64_t rdcycle() {
    uint64_t cycle;
    asm volatile ("rdcycle %0" : "=r"(cycle));
    return cycle;
}

// ========================== AES Accelerator API ==========================
int Aes256BlockOnCompletion(volatile int *completion_flag) {
    uint64_t dummy;
    ROCC_INSTRUCTION_D(AES256_OPCODE, dummy, FUNCT_CHECK_COMPLETION);
    asm volatile ("fence");
    while (!*completion_flag) asm volatile ("fence");
    return *completion_flag;
}

void Aes256AccelNonblocking(bool encrypt,
                            const unsigned char* data,
                            size_t data_length,
                            uint64_t key0,
                            uint64_t key1,
                            uint64_t key2,
                            uint64_t key3,
                            unsigned char* result,
                            int* success_flag) {
    assert(data_length % 16 == 0);

    ROCC_INSTRUCTION_SS(AES256_OPCODE, (uint64_t)data, data_length, FUNCT_SRC_INFO);
    ROCC_INSTRUCTION_SS(AES256_OPCODE, key0, key1, FUNCT_KEY_0);
    ROCC_INSTRUCTION_SS(AES256_OPCODE, key2, key3, FUNCT_KEY_1);
    ROCC_INSTRUCTION_S(AES256_OPCODE, encrypt, FUNCT_MODE);
    ROCC_INSTRUCTION_SS(AES256_OPCODE, (uint64_t)result, (uint64_t)success_flag, FUNCT_DEST_INFO);
}

int Aes256Accel(bool encrypt,
                const unsigned char* data,
                size_t data_length,
                uint64_t key0,
                uint64_t key1,
                uint64_t key2,
                uint64_t key3,
                unsigned char* result) {
    volatile int completion_flag = 0;
    Aes256AccelNonblocking(encrypt, data, data_length, key0, key1, key2, key3, result, (int*)&completion_flag);
    return Aes256BlockOnCompletion(&completion_flag);
}

// ========================== Main Test ==========================

#define AES_BLOCK_BYTES 16
#define BLOCKS 4
#define DATA_LEN (AES_BLOCK_BYTES * BLOCKS)

static unsigned char input[DATA_LEN] __attribute__((aligned(64)));
static unsigned char encrypted[DATA_LEN] __attribute__((aligned(64)));
static unsigned char decrypted[DATA_LEN] __attribute__((aligned(64)));

int main() {
#ifndef BAREMETAL
    if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0) {
      perror("mlockall failed");
      exit(1);
    }
#endif


    printf("Start Test\n");
    for (int i = 0; i < DATA_LEN; i++) input[i] = i;

    uint64_t key[4] = {0x0, 0x1, 0x2, 0x3};
    uint64_t start;
    uint64_t end;

    printf("Start Encrypt\n");
    start = rdcycle();
    Aes256Accel(true, 
                input, 
                DATA_LEN, 
                key[0], 
                key[1], 
                key[2], 
                key[3], 
                encrypted);
    end = rdcycle();

    printf("AES encrypt cycles: %lu\n", end - start);

    start = end = 0;

    start = rdcycle();
    printf("Start Decrypt\n");
    Aes256Accel(false, 
                encrypted, 
                DATA_LEN, 
                key[0], 
                key[1], 
                key[2], 
                key[3], 
                decrypted);
    end = rdcycle();
    printf("AES Decrypt cycles: %lu\n", end - start);

    for (int i = 0; i < DATA_LEN; i++) {
        if (input[i] != decrypted[i]) {
            printf("Mismatch at %d: expected %x, got %x\n", i, input[i], decrypted[i]);
            printf("TEST FAILED\n");
            return 1;
        }
    }

    printf("TEST PASSED\n");
    return 0;
}
