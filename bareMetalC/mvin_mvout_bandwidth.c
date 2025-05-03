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

#define N 8

#if (N*DIM) > (BANK_NUM*BANK_ROWS)
#error not enough scratchpad space
#endif

int main() {
#ifndef BAREMETAL
    if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0) {
      perror("mlockall failed");
      exit(1);
    }
#endif

  // printf("Flush\n");
  gemmini_flush(0);
  gemmini_config_ld(DIM * sizeof(elem_t));
  gemmini_config_st(DIM * sizeof(elem_t));

  static elem_t In[N][DIM][DIM] row_align(1);
  static elem_t Out[N][DIM][DIM] row_align(1);

  for (size_t n = 0; n < N; ++n)
    for (size_t i = 0; i < DIM; ++i)
      for (size_t j = 0; j < DIM; ++j)
        In[n][i][j] = i*DIM + j + n;

    // === Start performance monitoring ===
    counter_reset();
    counter_snapshot_reset();

    counter_configure(0, WDMA_BYTES_SENT);
    counter_configure(1, WDMA_TOTAL_LATENCY);

  for (size_t n = 0; n < N; ++n) {
    // printf("Mvin %d\n", n);
    gemmini_mvin(In[n], n*DIM);
    // printf("Mvout %d\n", n);
    gemmini_mvout(Out[n], n*DIM);
  }

  // printf("Fence");
  gemmini_fence();

  counter_snapshot_take();
  uint32_t bytes_sent = counter_read(0);
  uint32_t dma_latency = counter_read(1);
  // === End performance monitoring ===

  printf("[GEMMINI PERF] WDMA_BYTES_SENT = %u bytes\n", bytes_sent);
  printf("[GEMMINI PERF] WDMA_TOTAL_LATENCY = %u cycles\n", dma_latency);

  for (size_t n = 0; n < N; ++n)
  {
    if (!is_equal(In[n], Out[n])) {
      printf("Matrix %u:\n", n);
      printMatrix(In[n]);
      printf("Matrix %u output:\n", n);
      printMatrix(Out[n]);
      printf("\n");

      exit(1);
    }
      // printf("Matrix %u:\n", n);
      // printMatrix(In[n]);
      // printf("Matrix %u output:\n", n);
      // printMatrix(Out[n]);
      // printf("\n");
  }
  printf("TEST PASSED\n");
  exit(0);
}

