LIB_PATH=../target/release

LDFLAGS=-Lremap
CFLAGS=-I../include -g
export LD_LIBRARY_PATH=$(LIB_PATH)

example: example.c $(LIB_PATH)/libremap.so

$(LIB_PATH)/libremap.so:
	cargo build --release
