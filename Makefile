ALL: dist rawsocktest csocktest

.PHONY: clean

clean:
	rm -rf dist

dist:
	mkdir dist

rawsocktest: dist/rawsocktest

dist/rawsocktest: cmd/rawsocktest/*.go pkg/rawlayers/*.go
	go build -o dist/rawsocktest ./cmd/rawsocktest/...

csocktest: dist/csocktest

dist/csocktest: src/*
	cd src && make
	cp src/csocktest dist/
