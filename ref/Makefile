CFLAGS= -Wall -Wextra -O2 -g -fsanitize=address
CXXFLAGS= -Wall -Wextra -O2 -g -fsanitize=address
LDLIBS= -lasan

benchmark: MAC611.o Noekeon.o benchmark.o

clean:
	rm -f *.o

.PHONY: clean
