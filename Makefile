CC=g++
DEPS = tdh2.h timer.h
CFLAGS=-Iinclude -Llib -lbotan-3

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

build: src/demo.cpp src/tdh2_keys.cpp src/tdh2.cpp
	mkdir -p build
	$(CC) -o build/tdh2_demo src/demo.cpp src/tdh2_keys.cpp src/tdh2.cpp $(CFLAGS)
	./build/tdh2_demo

run:
	./build/tdh2_demo