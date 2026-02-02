COMPILER = clang
FLAGS = -O2 -g -Wall
MACROS = 
TARGET = -target bpf

ifdef TIME_NS
MACROS += -D TIME_WINDOW=$(TIME_NS)
endif

ifdef SIZE_B
MACROS += -D SIZE_WINDOW=$(SIZE_B)
endif

ifdef GROUP_S
MACROS += -D MAX_GROUP_SIZE=$(GROUP_S)
endif

ifdef MAX_FLOWS
MACROS += -D MAX_ENTRIES=$(MAX_FLOWS)
endif

# clang -O2 -g -Wall -target bpf -c <xdp>.c -o <xdp>.o

kern.o: kern.c
	$(COMPILER) $(FLAGS) $(TARGET) $(MACROS) -c kern.c -o kern.o

clean :
	rm -f kern.o
