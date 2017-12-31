

build:
	go build -o skrt ./

build-race:
	go build -o skrt -race ./

install:
	go install ./

clean:
	rm --force ./skrt

.PHONY: build build-race install
