all: dissector test

.PHONY : dissector
.PHONY : test

WIRESHARK := /usr/include/wireshark
export WIRESHARK
dissector:
	scons -C src

install:
	scons install -C src
    
test:
	make -C test

clean:
	scons -C src -c
	make clean -C test
