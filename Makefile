run: build
	./http2fuzz

client: build
	./http2fuzz --target localhost:1338
	
replay: build
	./http2fuzz --replay

build: 
	go build