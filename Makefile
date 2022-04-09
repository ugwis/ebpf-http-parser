CLANG = clang-9
CFLAGS = -O2 -g -Wall -Werror -Wunused-value

export BPF_CLANG := $(CLANG)
export BPF_CFLAGS := $(CFLAGS)

main:
	go generate
	go build -o parser .
