server:main.o
	g++ $^ -o $@ -lwfrest -lworkflow -lssl -lcrypt -lcrypto
main.o:main.cc
	g++ -c $^ -o $@
clean:
	rm -f main.o server