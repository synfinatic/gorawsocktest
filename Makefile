ALL: dist rawsocktest

.PHONY: clean

clean:
	rm -rf dist

dist:
	mkdir dist

rawsocktest: dist/rawsocktest

dist/rawsocktest: cmd/rawsocktest/*.go 
	go build -o dist/rawsocktest ./cmd/rawsocktest/...
