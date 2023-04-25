ALL: dist rawsocktest csocktest

.PHONY: clean

clean:
	rm -rf dist

dist:
	mkdir dist

rawsocktest: dist/rawsocktest

dist/rawsocktest: $(wildcard cmd/rawsocktest/*.go) $(wildcard pkg/rawlayers/*.go)
	go build -o dist/rawsocktest ./cmd/rawsocktest/...

csocktest: dist/csocktest

dist/csocktest: $(wildcard src/*.[ch])
	cd src && make
	cp src/csocktest dist/
