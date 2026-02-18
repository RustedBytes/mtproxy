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

    Copyright 2009-2013 Vkontakte Ltd
              2008-2013 Nikolai Durov
              2008-2013 Andrey Lopatin
              2011-2013 Oleg Davydov
              2012-2013 Arseny Smirnov
              2012-2013 Aliaksei Levin
              2012-2013 Anton Maydell
                   2013 Vitaliy Valtman

    Copyright 2014-2018 Telegram Messenger Inc
              2014-2018 Vitaly Valtman
*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

int change_user(const char *username);
int change_user_group(const char *username, const char *groupname);
int raise_file_rlimit(int maxfiles);

void print_backtrace(void);
void ksignal(int sig, void (*handler)(int));
void set_debug_handlers(void);

extern int start_time;

/* init_parse_option should be called before parse_option and parse_option_alias
 */
// void init_parse_options (int keep_mask, const unsigned char
// *keep_options_custom_list);
void init_parse_options(unsigned keep_mask,
                        const unsigned *keep_options_custom_list);

int parse_engine_options_long(int argc, char **argv);
int parse_usage(void);

int default_parse_option_func(int a);
void usage(void);

void parse_option_alias(const char *name, int val);
void parse_option_long_alias(const char *name, const char *alias_name);
void remove_parse_option(int val);
// void set_backlog (const char *arg);
// void set_maxconn (const char *arg);
long long parse_memory_limit(const char *s);

void add_builtin_parse_options(void);

#ifdef __cplusplus
}
#endif
