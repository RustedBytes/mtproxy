OBJ	=	objs
DEP	=	dep
EXE = ${OBJ}/bin
RUST_FFI_STATICLIB = target/debug/libmtproxy_ffi.a
RUST_FFI_STATICLIB_RELEASE = target/release/libmtproxy_ffi.a

COMMIT := $(shell git log -1 --pretty=format:"%H")

ARCH =
ifeq ($m, 32)
ARCH = -m32
endif
ifeq ($m, 64)
ARCH = -m64
endif

CFLAGS = $(ARCH) -O3 -std=gnu2x -Wall -Wno-array-bounds -mpclmul -march=core2 -mfpmath=sse -mssse3 -fno-strict-aliasing -fno-strict-overflow -fwrapv -DAES=1 -DCOMMIT=\"${COMMIT}\" -D_GNU_SOURCE=1 -D_FILE_OFFSET_BITS=64
LDFLAGS = $(ARCH) -ggdb -rdynamic -lm -lrt -lpthread

LIB = ${OBJ}/lib
CINCLUDE = -iquote common -iquote . -iquote rust/mtproxy-ffi/include

LIBLIST = ${LIB}/libkdb.a

PROJECTS = common jobs mtproto net crypto engine

OBJDIRS := ${OBJ} $(addprefix ${OBJ}/,${PROJECTS}) ${EXE} ${LIB}
DEPDIRS := ${DEP} $(addprefix ${DEP}/,${PROJECTS})
ALLDIRS := ${DEPDIRS} ${OBJDIRS}


.PHONY:	all clean test release release-legacy step15-inventory ffi-freeze

EXELIST	:= ${EXE}/mtproto-proxy
# Legacy C-wrapper build path remains transitional.
# Canonical runtime entrypoint is rust/mtproxy-bin (mtproxy-rust).
RUST_OBJECTS	=	\
  ${OBJ}/mtproto/mtproto-proxy.rust.o ${OBJ}/mtproto/mtproto-config.o ${OBJ}/net/net-tcp-rpc-ext-server.o
RUST_OBJECTS_COMMON	=	\
  ${OBJ}/mtproto/mtproto-config.o ${OBJ}/net/net-tcp-rpc-ext-server.o
RUST_RS_SOURCES := $(shell find rust/mtproxy-core/src rust/mtproxy-ffi/src -type f -name '*.rs')
RUST_RUNTIME_RELEASE = target/release/mtproxy-rust

DEPENDENCE_CXX		:=	$(subst ${OBJ}/,${DEP}/,$(patsubst %.o,%.d,${OBJECTS_CXX}))
DEPENDENCE_STRANGE	:=	$(subst ${OBJ}/,${DEP}/,$(patsubst %.o,%.d,${OBJECTS_STRANGE}))
DEPENDENCE_RUST	:=	$(subst ${OBJ}/,${DEP}/,$(patsubst %.o,%.d,${RUST_OBJECTS}))

LIB_OBJS_NORMAL := \
	${OBJ}/common/parse-config.o \
	${OBJ}/jobs/jobs.o \
	${OBJ}/common/mp-queue-rust.o \
	${OBJ}/net/net-events.o ${OBJ}/net/net-msg.o ${OBJ}/net/net-msg-buffers.o \
	${OBJ}/net/net-config.o ${OBJ}/net/net-crypto-aes.o ${OBJ}/net/net-crypto-dh.o \
	${OBJ}/net/net-connections.o \
	${OBJ}/net/net-rpc-targets.o \
	${OBJ}/net/net-tcp-connections.o ${OBJ}/net/net-tcp-rpc-common.o ${OBJ}/net/net-tcp-rpc-client.o ${OBJ}/net/net-tcp-rpc-server.o \
	${OBJ}/net/net-http-server.o \
	${OBJ}/common/tl-parse.o ${OBJ}/common/common-stats.o \
	${OBJ}/engine/engine.o ${OBJ}/engine/engine-signals.o \
	${OBJ}/engine/engine-net.o \
	${OBJ}/engine/engine-rpc.o \
	${OBJ}/engine/engine-rpc-common.o \
	${OBJ}/net/net-thread.o ${OBJ}/net/net-stats.o \
	${OBJ}/common/kprintf.o \
	${OBJ}/common/precise-time.o \
	${OBJ}/common/rust-ffi-bridge.o \

LIB_OBJS := ${LIB_OBJS_NORMAL}

DEPENDENCE_LIB	:=	$(subst ${OBJ}/,${DEP}/,$(patsubst %.o,%.d,${LIB_OBJS}))

DEPENDENCE_ALL		:=	${DEPENDENCE_RUST} ${DEPENDENCE_STRANGE} ${DEPENDENCE_LIB}

OBJECTS_ALL		:=	${RUST_OBJECTS} ${LIB_OBJS}

all:	${ALLDIRS} ${EXELIST}
dirs: ${ALLDIRS}
create_dirs_and_headers: ${ALLDIRS} 

${ALLDIRS}:	
	@test -d $@ || mkdir -p $@

-include ${DEPENDENCE_ALL}

${RUST_OBJECTS_COMMON}: ${OBJ}/%.o: %.c | create_dirs_and_headers
	${CC} ${CFLAGS} ${CINCLUDE} -c -MP -MD -MF ${DEP}/$*.d -MQ ${OBJ}/$*.o -o $@ $<

${OBJ}/mtproto/mtproto-proxy.rust.o: mtproto/mtproto-proxy.c | create_dirs_and_headers
	${CC} ${CFLAGS} -DUSE_RUST_FFI=1 ${CINCLUDE} -c -MP -MD -MF ${DEP}/mtproto/mtproto-proxy.rust.d -MQ ${OBJ}/mtproto/mtproto-proxy.rust.o -o $@ $<

${LIB_OBJS_NORMAL}: ${OBJ}/%.o: %.c | create_dirs_and_headers
	${CC} ${CFLAGS} -fpic ${CINCLUDE} -c -MP -MD -MF ${DEP}/$*.d -MQ ${OBJ}/$*.o -o $@ $<

${EXELIST}: ${LIBLIST}

${EXE}/mtproto-proxy: ${RUST_OBJECTS} ${LIB}/libkdb.a ${RUST_FFI_STATICLIB}
	${CC} -o $@ ${RUST_OBJECTS} ${LIB}/libkdb.a ${RUST_FFI_STATICLIB} ${LIB}/libkdb.a ${RUST_FFI_STATICLIB} ${LDFLAGS} -ldl

${RUST_FFI_STATICLIB}: Cargo.toml Cargo.lock rust/mtproxy-core/Cargo.toml rust/mtproxy-ffi/Cargo.toml ${RUST_RS_SOURCES}
	cargo build  -p mtproxy-ffi

${RUST_FFI_STATICLIB_RELEASE}: Cargo.toml Cargo.lock rust/mtproxy-core/Cargo.toml rust/mtproxy-ffi/Cargo.toml ${RUST_RS_SOURCES}
	cargo build --release -p mtproxy-ffi

${RUST_RUNTIME_RELEASE}: Cargo.toml Cargo.lock rust/mtproxy-bin/Cargo.toml rust/mtproxy-core/Cargo.toml ${RUST_RS_SOURCES}
	cargo build --release -p mtproxy-bin --bin mtproxy-rust

release: ${ALLDIRS} ${RUST_RUNTIME_RELEASE}
	cp ${RUST_RUNTIME_RELEASE} ${EXE}/mtproxy-rust

release-legacy: ${ALLDIRS} ${RUST_OBJECTS} ${LIB}/libkdb.a ${RUST_FFI_STATICLIB_RELEASE}
	${CC} -o ${EXE}/mtproto-proxy ${RUST_OBJECTS} ${LIB}/libkdb.a ${RUST_FFI_STATICLIB_RELEASE} ${LIB}/libkdb.a ${RUST_FFI_STATICLIB_RELEASE} ${LDFLAGS} -ldl

${LIB}/libkdb.a: ${LIB_OBJS}
	rm -f $@ && ar rcs $@ $^

clean:
	rm -rf ${OBJ} ${DEP} ${EXE} target || true

force-clean: clean

test: all
	./tests/run.sh

ffi-freeze:
	./scripts/ffi_freeze_check.sh

step15-inventory:
	./scripts/generate_refactor_manifest.sh
