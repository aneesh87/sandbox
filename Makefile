fend: fend.o
	gcc -o fend fend.o

fend.o: fend.c
	gcc -c fend.c -o fend.o

clean:
	-rm -f *.o
	-rm -f fend
