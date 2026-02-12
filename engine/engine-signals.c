/*
    This file is part of Mtproto-proxy Library.

    Mtproto-proxy Library is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation, either version 2 of the License,
   or (at your option) any later version.

    Mtproto-proxy Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with Mtproto-proxy Library.  If not, see
   <http://www.gnu.org/licenses/>.

    Copyright 2013 Vkontakte Ltd
              2013 Vitaliy Valtman
              2013 Anton Maydell

    Copyright 2014 Telegram Messenger Inc
              2014 Vitaly Valtman
              2014 Anton Maydell

    Copyright 2015-2016 Telegram Messenger Inc
              2015-2016 Vitaliy Valtman
*/
#include <assert.h>
#include <signal.h>
#include <stdint.h>
#include <unistd.h>

#include "common/kprintf.h"
#include "common/server-functions.h"

#include "engine/engine-signals.h"
#include "engine/engine.h"
#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

void engine_set_terminal_attributes(void) __attribute__((weak));
void engine_set_terminal_attributes(void) {}

void signal_set_pending(int sig) {
  mtproxy_ffi_engine_signal_set_pending(sig);
}

int signal_check_pending(int sig) {
  return mtproxy_ffi_engine_signal_check_pending(sig);
}

int signal_check_pending_and_clear(int sig) {
  return mtproxy_ffi_engine_signal_check_pending_and_clear(sig);
}

void sigint_immediate_handler([[maybe_unused]] const int sig) {
  static const char message[] = "SIGINT handled immediately.\n";
  kwrite(2, message, sizeof(message) - (size_t)1);
  engine_set_terminal_attributes();
  _exit(1);
}

void sigterm_immediate_handler([[maybe_unused]] const int sig) {
  static const char message[] = "SIGTERM handled immediately.\n";
  kwrite(2, message, sizeof(message) - (size_t)1);
  engine_set_terminal_attributes();
  _exit(1);
}

void sigint_handler(const int sig) {
  static const char message[] = "SIGINT handled.\n";
  kwrite(2, message, sizeof(message) - (size_t)1);
  signal_set_pending(SIGINT);
  ksignal(sig, sigint_immediate_handler);
}

void sigterm_handler(const int sig) {
  static const char message[] = "SIGTERM handled.\n";
  kwrite(2, message, sizeof(message) - (size_t)1);
  signal_set_pending(SIGTERM);
  ksignal(sig, sigterm_immediate_handler);
}

static const char sig_message[] = "received signal ??\n";

void default_signal_handler(const int sig) {
  char msg[sizeof(sig_message)];
  for (size_t i = 0; i < sizeof(sig_message); i++) {
    msg[i] = sig_message[i];
  }
  msg[sizeof(sig_message) - 4] = '0' + (sig / 10);
  msg[sizeof(sig_message) - 3] = '0' + (sig % 10);
  kwrite(2, msg, sizeof(sig_message) - (size_t)1);

  signal_set_pending(sig);
}

void quiet_signal_handler(const int sig) {
  if (verbosity >= 1) {
    char msg[sizeof(sig_message)];
    for (size_t i = 0; i < sizeof(sig_message); i++) {
      msg[i] = sig_message[i];
    }
    msg[sizeof(sig_message) - 4] = '0' + (sig / 10);
    msg[sizeof(sig_message) - 3] = '0' + (sig % 10);
    kwrite(2, msg, sizeof(sig_message) - (size_t)1);
  }

  signal_set_pending(sig);
}

void empty_signal_handler([[maybe_unused]] const int sig) {}

int interrupt_signal_raised(void) {
  return mtproxy_ffi_engine_interrupt_signal_raised();
}

typedef struct engine_signal_dispatch_ctx {
  server_functions_t *F;
  uint64_t allowed_signals;
} engine_signal_dispatch_ctx_t;

static void engine_signal_dispatch_from_rust(int32_t sig, void *ctx) {
  auto dispatch_ctx = (engine_signal_dispatch_ctx_t *)ctx;
  if (dispatch_ctx == nullptr || dispatch_ctx->F == nullptr || sig <= 0 ||
      sig > OUR_SIGRTMAX) {
    return;
  }

  if ((dispatch_ctx->allowed_signals & SIG2INT(sig)) == 0) {
    return;
  }

  assert(dispatch_ctx->F->signal_handlers[sig]);
  dispatch_ctx->F->signal_handlers[sig]();
}

int engine_process_signals(void) {
  auto E = engine_state;
  auto F = E->F;
  engine_signal_dispatch_ctx_t ctx = {
      .F = F,
      .allowed_signals = F->allowed_signals,
  };

  int processed = mtproxy_ffi_engine_process_signals_allowed(
      F->allowed_signals, engine_signal_dispatch_from_rust, &ctx);
  assert(processed >= 0);

  return 1;
}
