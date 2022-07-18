// RUN: %clangxx_tsan %s -o %t
// RUN: %run %t 2>&1 | FileCheck %s

// bench.h needs pthread barriers which are not available on OS X
// UNSUPPORTED: darwin

#include "bench.h"
#include <atomic>
#include <vector>

struct Block {
  volatile long data[32 << 10];
};

Block* queue;
std::atomic<long> step;
std::atomic<long> ref;
std::atomic<long> fake;
std::atomic<long> reset[1000];
int histogram[64];

void thread(int tid) {
  if (tid == 0) {
    uint64_t start = nanotime();
    for (int i = 0; i < bench_niter; i++) {
      Block* b = new Block;
      fake++;
      for (auto& data : b->data)
        data = 1;
      while (i != 0 && ref != bench_nthread / 2)
        pthread_yield();
      Block* prev = queue;
      queue = b;
      ref = 0;
      step++;
      delete prev;
      uint64_t now = nanotime();
      uint64_t time_ms = (now - start) / 1000000;
      start = now;
      int idx = 0;
      for (;time_ms; time_ms /= 2, idx++) {}
      histogram[idx]++;
    }
    int first = 64, last = 64;
    for (int i = 0; i < 64; i++) {
      if (!histogram[i])
        continue;
      if (first == 64)
        first = i;
      last = i + 1;
    }    
    for (uint64_t ms = 1; first < last; first++, ms *= 2)
      printf("<%-6lums: %d\n", ms, histogram[first]);
  } else if (tid % 2) {
    for (int i = 0; i < bench_niter; i++) {
      while (step != i + 1)
        usleep(10);
      Block* b = queue;
      for (auto data : b->data) {
        if (data != 1)
          exit(1);
      }
      ref++;
    }
  } else {
    while (step < bench_niter)
      reset[(tid / 2) % (sizeof(reset)/sizeof(reset[0]))]++;
  }
}

void bench() {
  start_thread_group(bench_nthread, thread);
}

// CHECK: DONE
