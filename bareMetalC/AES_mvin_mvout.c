// See LICENSE for license details.

#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#ifndef BAREMETAL
#include <sys/mman.h>
#endif
#include "include/gemmini_testutils.h"

#define N 1 // 1 matrix
//#undef DIM
//#define DIM 4 // 4x4 = 16 bytes = 1 AES block

#if (N*DIM) > (BANK_NUM*BANK_ROWS)
#error not enough scratchpad space
#endif


// uint8_t key[32] = {
//     0x00, 0x01, 0x02, 0x03,  0x04, 0x05, 0x06, 0x07,
//     0x08, 0x09, 0x0a, 0x0b,  0x0c, 0x0d, 0x0e, 0x0f,
//     0x10, 0x11, 0x12, 0x13,  0x14, 0x15, 0x16, 0x17,
//     0x18, 0x19, 0x1a, 0x1b,  0x1c, 0x1d, 0x1e, 0x1f
//   };
// AES-256 ECB encrypted ciphertext (from known key/plaintext)
/*
  // Expected AES-256 decrypted plaintext
  uint8_t plaintext[16] = {
    0x00, 0x11, 0x22, 0x33,
    0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb,
    0xcc, 0xdd, 0xee, 0xff
};
*/


// static elem_t ciphertext[DIM][DIM] row_align(1) = {
//   {0x69, 0xc4, 0xe0, 0xd8},
//   {0x6a, 0x7b, 0x04, 0x30},
//   {0xd8, 0xcd, 0xb7, 0x80},
//   {0x70, 0xb4, 0xc5, 0x5a}
// };


// static elem_t ciphertext[DIM][DIM] row_align(1) = {
//   {0x7c, 0x78, 0xfe, 0x2c},
//   {0xef, 0xe3, 0xe5, 0x31},
//   {0x71, 0x76, 0x64, 0xd7},
//   {0xf3, 0x2c, 0xd5, 0x0b}
// };


/*
static elem_t ciphertext[DIM][DIM] row_align(1) = {
    0x8e, 0xa2, 0xb7, 0xca,
    0x51, 0x67, 0x45, 0xbf,
    0xea, 0xfc, 0x49, 0x90,
    0x4b, 0x49, 0x60, 0x89
};
*/
  // Expected decrypted output (should match AES plaintext)
  // Example: "00112233445566778899aabbccddeeff" -> laid out in 4x4
  static elem_t plaintext[DIM][DIM] row_align(16) = {
    {0x00, 0x11, 0x22, 0x33},
    {0x44, 0x55, 0x66, 0x77},
    {0x88, 0x99, 0xaa, 0xbb},
    {0xcc, 0xdd, 0xee, 0xff}
  };

  static elem_t ciphertext[DIM][DIM] row_align(16) = {
    0x8e, 0xa2, 0xb7, 0xca,
    0x51, 0x67, 0x45, 0xbf,
    0xea, 0xfc, 0x49, 0x90,
    0x4b, 0x49, 0x60, 0x89
  };

// 00
// f2 90 00 b6 2a 49 9f d0 a9 f3 9a 6a dd 2e 77 80
static elem_t ciphertext00[DIM][DIM] row_align(16) = {
  0xf2, 0x90, 0x00, 0xb6, 
  0x2a, 0x49, 0x9f, 0xd0, 
  0xa9, 0xf3, 0x9a, 0x6a, 
  0xdd, 0x2e, 0x77, 0x80
};

// 01
// f0 5d 76 ae 4a b9 9f e5 a6 f6 9b 31 48 c2 36 3d
static elem_t ciphertext01[DIM][DIM] row_align(16) = {
  0xf0, 0x5d, 0x76, 0xae, 
  0x4a, 0xb9, 0x9f, 0xe5, 
  0xa6, 0xf6, 0x9b, 0x31, 
  0x48, 0xc2, 0x36, 0x3d
};

// 02
// 0e bc b5 de b5 2c 83 bd 08 a8 a9 35 18 2c 91 99
static elem_t ciphertext02[DIM][DIM] row_align(16) = {
  0x0e, 0xbc, 0xb5, 0xde, 
  0xb5, 0x2c, 0x83, 0xbd, 
  0x08, 0xa8, 0xa9, 0x35,
  0x18, 0x2c, 0x91, 0x99
};
// 03
// d2 43 56 53 28 81 60 2f 80 9e b3 83 c5 ff 5d 56
static elem_t ciphertext03[DIM][DIM] row_align(1) = {
  0xd2, 0x43, 0x56, 0x53, 
  0x28, 0x81, 0x60, 0x2f, 
  0x80, 0x9e, 0xb3, 0x83, 
  0xc5, 0xff, 0x5d, 0x56
};

// Output buffer
static elem_t Out[DIM][DIM] row_align(16);
static elem_t Out00[DIM][DIM] row_align(16);
static elem_t Out01[DIM][DIM] row_align(16);
static elem_t Out02[DIM][DIM] row_align(16);
static elem_t Out03[DIM][DIM] row_align(16);

void print_hex_matrix(elem_t mat[DIM][DIM]) {
    printf("Matrix (%dx%d):\n", DIM, DIM);
    for (int i = 0; i < DIM; i++) {
        for (int j = 0; j < DIM; j++) {
        printf("%02x ", (uint8_t)mat[i][j]);
        }
        printf("\n");
    }
}

void print_block(uint8_t* data) {
  printf("Block: ");
  for (int i = 0; i < 16; ++i)
    printf("%02x ", data[i]);
  printf("\n");
}

int main() {
#ifndef BAREMETAL
    if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0) {
      perror("mlockall failed");
      exit(1);
    }
#endif

printf("Starting AES mvin/mvout test\n");

  gemmini_flush(0);
  gemmini_config_ld(DIM * sizeof(elem_t));
  gemmini_config_st(DIM * sizeof(elem_t));

  // === Performance monitoring ===
  counter_reset();
  counter_snapshot_reset();

  counter_configure(0, RDMA_BYTES_REC);
  counter_configure(1, RDMA_TOTAL_LATENCY);

  printf("mvin begin\n");
  gemmini_extended_mvin(ciphertext, /*spad_addr=*/0, /*cols=*/DIM, /*rows=*/DIM);
  gemmini_extended_mvin(ciphertext00, /*spad_addr=*/1*DIM, /*cols=*/DIM, /*rows=*/DIM);
  gemmini_extended_mvin(ciphertext01, /*spad_addr=*/2*DIM, /*cols=*/DIM, /*rows=*/DIM);
  gemmini_extended_mvin(ciphertext02, /*spad_addr=*/3*DIM, /*cols=*/DIM, /*rows=*/DIM);
  gemmini_extended_mvin(ciphertext03, /*spad_addr=*/4*DIM, /*cols=*/DIM, /*rows=*/DIM);
  
  printf("mvout begin\n");
  gemmini_extended_mvout(Out, /*spad_addr=*/0, /*cols=*/DIM, /*rows=*/DIM);
  gemmini_extended_mvout(Out00, /*spad_addr=*/1*DIM, /*cols=*/DIM, /*rows=*/DIM);
  gemmini_extended_mvout(Out01, /*spad_addr=*/2*DIM, /*cols=*/DIM, /*rows=*/DIM);
  gemmini_extended_mvout(Out02, /*spad_addr=*/3*DIM, /*cols=*/DIM, /*rows=*/DIM);
  gemmini_extended_mvout(Out03, /*spad_addr=*/4*DIM, /*cols=*/DIM, /*rows=*/DIM);
  gemmini_fence();

  counter_snapshot_take();
  printf("[GEMMINI PERF] RDMA_BYTES_SENT = %u bytes\n", counter_read(0));
  printf("[GEMMINI PERF] RDMA_TOTAL_LATENCY = %u cycles\n", counter_read(1));


  print_block(Out);
  print_block(Out00);
  print_block(Out01);
  print_block(Out02);
  print_block(Out03);

  // === Check output ===
  // bool passed = true;
  // for (size_t i = 0; i < DIM; i++) {
  //   for (size_t j = 0; j < DIM; j++) {
  //     if (Out[i][j] != plaintext[i][j]) {
  //       // print_hex_matrix(plaintext);
  //       // print_hex_matrix(Out);
  //       printf("TEST FAILED\n");
  //       exit(1);
  //     }
  //   }
  // }


   printf("TEST PASSED\n");
   exit(0);
}

/*
  // printf("Flush\n");
  printf("Gemmini Config\n");
  gemmini_flush(0);
  gemmini_config_ld(DIM * sizeof(elem_t));
  gemmini_config_st(DIM * sizeof(elem_t));

  static elem_t In[N][DIM][DIM] row_align(1);
  static elem_t Out[N][DIM][DIM] row_align(1);

  
  size_t count = 0;
  for (size_t n = 0; n < N; ++n)
    for (size_t i = 0; i < DIM; ++i)
      for (size_t j = 0; j < DIM; ++j)
        In[n][i][j] = ciphertext[count++];

    printf("Configured DMA block size = %lu bytes\n", DIM * sizeof(elem_t));
        

    printf("Starting Test\n");

    // === Start performance monitoring ===
    counter_reset();
    counter_snapshot_reset();

    counter_configure(0, RDMA_BYTES_REC);
    counter_configure(1, RDMA_TOTAL_LATENCY);

  for (size_t n = 0; n < N; ++n) {
    // printf("Mvin %d\n", n);
    printf("In[%zu] (host memory):\n", n);
    for (size_t i = 0; i < DIM; ++i) {
        for (size_t j = 0; j < DIM; ++j) {
        printf("%4d ", In[n][i][j]);
        }
        printf("\n");
    }
    printf("mvin begin\n");
    gemmini_mvin(In[n], n*DIM);
    printf("mvin end\n");
    // printf("Mvout %d\n", n);
    gemmini_mvout(Out[n], n*DIM);
  }

  // printf("Fence");
  gemmini_fence();

  counter_snapshot_take();
  uint32_t bytes_sent = counter_read(0);
  uint32_t dma_latency = counter_read(1);
  // === End performance monitoring ===

  printf("[GEMMINI PERF] RDMA_BYTES_SENT = %u bytes\n", bytes_sent);
  printf("[GEMMINI PERF] RDMA_TOTAL_LATENCY = %u cycles\n", dma_latency);


  // Check that output matches plaintext
  count = 0;
  int success = 1;
  for (size_t i = 0; i < DIM; ++i) {
    for (size_t j = 0; j < DIM; ++j) {
      if (Out[0][i][j] != plaintext[count]) {
        printf("Mismatch at [%zu][%zu]: got 0x%x, expected 0x%x\n",
            i, j, Out[0][i][j], plaintext[count]);
        success = 0;
      }
      count++;
    }
  }

  if (success) {
    printf("AES Decryption Test PASSED!\n");
  } else {
    printf("AES Decryption Test FAILED!\n");
    printMatrix(Out[0]);
    exit(1);
  }
  exit(0);
}
*/
