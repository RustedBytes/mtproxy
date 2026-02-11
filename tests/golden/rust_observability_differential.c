#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

static int test_statm_parser(void) {
  const char *statm = "10 20 30 40 50 60 70\n";
  int64_t out[7] = {0};
  if (mtproxy_ffi_parse_statm(statm, strlen(statm), 6, 4096, out) != 0) {
    fprintf(stderr, "parse_statm call failed\n");
    return -1;
  }
  if (out[0] != 10LL * 4096 || out[1] != 20LL * 4096 || out[5] != 60LL * 4096) {
    fprintf(stderr, "parse_statm values mismatch\n");
    return -1;
  }
  return 0;
}

static int test_meminfo_parser(void) {
  const char *meminfo =
      "MemTotal:       16000000 kB\n"
      "MemFree:         1000000 kB\n"
      "Cached:          2000000 kB\n"
      "SwapTotal:        500000 kB\n"
      "SwapFree:         125000 kB\n";
  mtproxy_ffi_meminfo_summary_t s = {0};
  if (mtproxy_ffi_parse_meminfo_summary(meminfo, strlen(meminfo), &s) != 0) {
    fprintf(stderr, "parse_meminfo_summary call failed\n");
    return -1;
  }
  if (s.mem_free != (1000000LL << 10) || s.mem_cached != (2000000LL << 10) ||
      s.swap_total != (500000LL << 10) || s.swap_free != (125000LL << 10) || s.found_mask != 15) {
    fprintf(stderr, "parse_meminfo_summary values mismatch\n");
    return -1;
  }
  return 0;
}

static int test_log_prefix_formatter(void) {
  char out[128];
  int n = mtproxy_ffi_format_log_prefix(321, 2026, 2, 11, 12, 34, 56, 789, out, sizeof(out));
  if (n <= 0) {
    fprintf(stderr, "format_log_prefix call failed\n");
    return -1;
  }
  const char *expected = "[321][2026-02-11 12:34:56.000789 local] ";
  if (strcmp(out, expected)) {
    fprintf(stderr, "format_log_prefix mismatch:\n got: %s\n exp: %s\n", out, expected);
    return -1;
  }
  return 0;
}

static int test_proc_stat_line_parser(void) {
  const char *line =
      "123 (cmd) R 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39\n";
  mtproxy_ffi_proc_stats_t s = {0};
  if (mtproxy_ffi_parse_proc_stat_line(line, strlen(line), &s) != 0) {
    fprintf(stderr, "parse_proc_stat_line call failed\n");
    return -1;
  }
  if (s.pid != 123 || s.state != 'R' || s.ppid != 1 || s.pgrp != 2 || s.delayacct_blkio_ticks != 39) {
    fprintf(stderr, "parse_proc_stat_line field mismatch\n");
    return -1;
  }
  if (strncmp(s.comm, "(cmd)", 5) != 0) {
    fprintf(stderr, "parse_proc_stat_line comm mismatch\n");
    return -1;
  }
  return 0;
}

static int test_proc_stat_file_reader(void) {
  mtproxy_ffi_proc_stats_t s = {0};
  int pid = getpid();
  if (mtproxy_ffi_read_proc_stat_file(pid, 0, &s) != 0) {
    fprintf(stderr, "read_proc_stat_file call failed for pid=%d\n", pid);
    return -1;
  }
  if (s.pid != pid || s.comm[0] == 0) {
    fprintf(stderr, "read_proc_stat_file result mismatch\n");
    return -1;
  }
  return 0;
}

int main(void) {
  if (test_statm_parser() < 0) {
    return 1;
  }
  if (test_meminfo_parser() < 0) {
    return 1;
  }
  if (test_log_prefix_formatter() < 0) {
    return 1;
  }
  if (test_proc_stat_line_parser() < 0) {
    return 1;
  }
  if (test_proc_stat_file_reader() < 0) {
    return 1;
  }

  puts("rust_observability_differential: ok");
  return 0;
}
