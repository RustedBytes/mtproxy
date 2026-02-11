#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

typedef struct {
  size_t advance;
  int line_no;
  int ch;
} ref_scan_t;

typedef struct {
  long long value;
  size_t consumed;
} ref_int_t;

static ref_scan_t ref_skipspc(const char *cur, size_t len, int line_no) {
  size_t i = 0;
  while (i < len) {
    unsigned char ch = (unsigned char)cur[i];
    if (ch == ' ' || ch == '\t' || ch == '\r') {
      i++;
      continue;
    }
    if (ch == '\n') {
      line_no++;
      i++;
      continue;
    }
    if (ch == '#') {
      i++;
      while (i < len && cur[i] != '\n') {
        i++;
      }
      continue;
    }
    break;
  }
  return (ref_scan_t){.advance = i,
                      .line_no = line_no,
                      .ch = i < len ? (unsigned char)cur[i] : 0};
}

static ref_scan_t ref_skspc(const char *cur, size_t len, int line_no) {
  size_t i = 0;
  while (i < len && (cur[i] == ' ' || cur[i] == '\t')) {
    i++;
  }
  return (ref_scan_t){.advance = i,
                      .line_no = line_no,
                      .ch = i < len ? (unsigned char)cur[i] : 0};
}

static int ref_is_word_char(unsigned char ch) {
  return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
         (ch >= '0' && ch <= '9') || ch == '.' || ch == '-' || ch == '_';
}

static int ref_getword_len(const char *cur, size_t len) {
  ref_scan_t scan = ref_skspc(cur, len, 0);
  size_t i = scan.advance;
  if (i >= len) {
    return 0;
  }
  if (cur[i] != '[') {
    while (i < len && ref_is_word_char((unsigned char)cur[i])) {
      i++;
    }
    return (int)(i - scan.advance);
  }
  i++;
  while (i < len &&
         (ref_is_word_char((unsigned char)cur[i]) || cur[i] == ':')) {
    i++;
  }
  if (i < len && cur[i] == ']') {
    i++;
  }
  return (int)(i - scan.advance);
}

static int ref_getstr_len(const char *cur, size_t len) {
  ref_scan_t scan = ref_skspc(cur, len, 0);
  size_t i = scan.advance;
  if (i >= len) {
    return 0;
  }
  if (cur[i] == '"') {
    return 1;
  }
  while (i < len && (unsigned char)cur[i] > ' ' && cur[i] != ';') {
    i++;
  }
  return (int)(i - scan.advance);
}

static ref_int_t ref_getint(const char *cur, size_t len) {
  ref_scan_t scan = ref_skspc(cur, len, 0);
  size_t i = scan.advance;
  long long x = 0;
  while (i < len && cur[i] >= '0' && cur[i] <= '9') {
    x = x * 10 + (cur[i] - '0');
    i++;
  }
  return (ref_int_t){.value = x, .consumed = i - scan.advance};
}

static ref_int_t ref_getint_zero(const char *cur, size_t len) {
  ref_int_t r = ref_getint(cur, len);
  if (!r.consumed) {
    r.value = -1;
  }
  return r;
}

static ref_int_t ref_getint_signed_zero(const char *cur, size_t len) {
  ref_scan_t scan = ref_skspc(cur, len, 0);
  size_t i = scan.advance;
  int sign = 1;
  if (i < len && cur[i] == '-') {
    sign = -1;
    i++;
  }
  size_t start = i;
  long long x = 0;
  while (i < len && cur[i] >= '0' && cur[i] <= '9') {
    x = x * 10 + sign * (cur[i] - '0');
    i++;
  }
  if (i == start) {
    return (ref_int_t){.value = (-1LL << 63), .consumed = 0};
  }
  return (ref_int_t){.value = x, .consumed = i - scan.advance};
}

static int test_case(const char *src) {
  size_t len = strlen(src);
  for (size_t off = 0; off <= len; off++) {
    const char *cur = src + off;
    size_t rem = len - off;

    ref_scan_t rs = ref_skipspc(cur, rem, 7);
    mtproxy_ffi_cfg_scan_result_t ms = {0};
    if (mtproxy_ffi_cfg_skipspc(cur, rem, 7, &ms) != 0 ||
        ms.advance != rs.advance || ms.line_no != rs.line_no ||
        ms.ch != rs.ch) {
      fprintf(stderr, "cfg_skipspc mismatch at off=%zu\n", off);
      return -1;
    }

    rs = ref_skspc(cur, rem, 13);
    ms = (mtproxy_ffi_cfg_scan_result_t){0};
    if (mtproxy_ffi_cfg_skspc(cur, rem, 13, &ms) != 0 ||
        ms.advance != rs.advance || ms.line_no != rs.line_no ||
        ms.ch != rs.ch) {
      fprintf(stderr, "cfg_skspc mismatch at off=%zu\n", off);
      return -1;
    }

    int rw = ref_getword_len(cur, rem);
    int mw = mtproxy_ffi_cfg_getword_len(cur, rem);
    if (rw != mw) {
      fprintf(stderr, "cfg_getword_len mismatch at off=%zu ref=%d ffi=%d\n",
              off, rw, mw);
      return -1;
    }

    int rg = ref_getstr_len(cur, rem);
    int mg = mtproxy_ffi_cfg_getstr_len(cur, rem);
    if (rg != mg) {
      fprintf(stderr, "cfg_getstr_len mismatch at off=%zu ref=%d ffi=%d\n", off,
              rg, mg);
      return -1;
    }

    ref_int_t ri = ref_getint(cur, rem);
    mtproxy_ffi_cfg_int_result_t mi = {0};
    if (mtproxy_ffi_cfg_getint(cur, rem, &mi) != 0 ||
        (long long)mi.value != ri.value || mi.consumed != ri.consumed) {
      fprintf(stderr, "cfg_getint mismatch at off=%zu\n", off);
      return -1;
    }

    ri = ref_getint_zero(cur, rem);
    mi = (mtproxy_ffi_cfg_int_result_t){0};
    if (mtproxy_ffi_cfg_getint_zero(cur, rem, &mi) != 0 ||
        (long long)mi.value != ri.value || mi.consumed != ri.consumed) {
      fprintf(stderr, "cfg_getint_zero mismatch at off=%zu\n", off);
      return -1;
    }

    ri = ref_getint_signed_zero(cur, rem);
    mi = (mtproxy_ffi_cfg_int_result_t){0};
    if (mtproxy_ffi_cfg_getint_signed_zero(cur, rem, &mi) != 0 ||
        (long long)mi.value != ri.value || mi.consumed != ri.consumed) {
      fprintf(stderr, "cfg_getint_signed_zero mismatch at off=%zu\n", off);
      return -1;
    }
  }
  return 0;
}

int main(void) {
  static const char *cases[] = {
      "",
      "  \t# c1\nproxy 127.0.0.1:443;",
      "proxy_for -2 [::1]:443;",
      "min_connections 10;\nmax_connections 200;\n",
      "default -12345; timeout 1000;",
      "\"quoted\" ; [2001:db8::1]:80",
      "# only-comment-without-newline",
  };

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    if (test_case(cases[i]) < 0) {
      fprintf(stderr, "failed on case %zu: %s\n", i, cases[i]);
      return 1;
    }
  }

  puts("rust_config_lexer_differential: ok");
  return 0;
}
