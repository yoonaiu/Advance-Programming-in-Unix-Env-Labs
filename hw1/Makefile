all: sandbox.cpp
	rm -f sandbox.so
	g++ -o sandbox.so -shared -fPIC -ldl sandbox.cpp
	rm -f index.html*
	rm -f *.log
	chmod +x launcher