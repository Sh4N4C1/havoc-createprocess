BOFNAME := createprocess
CC_x64 := x86_64-w64-mingw32-gcc

all:
	$(CC_x64) -o ./bin/$(BOFNAME).x64.o -Os -Iinclude -c ./src/entry.c -DBOF 

