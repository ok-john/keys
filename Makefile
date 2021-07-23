CC := go
CFLAGS := build
SHELL := /bin/bash
OUT_DIR := bin
MOD_NAME := keys

default: all

all: deps test lint compile
verb: deps test-verbose compile
secp: deps test-secp compile

install-deps:
	sudo snap install gosec
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.41.1
	golangci-lint --version

deps:
	$(CC) get ./... && $(CC) mod tidy

lint:
	./lint.sh

sec:
	./security.sh

compile:
	$(CC) $(CFLAGS) ./...

test:
	$(CC) test ./...

test-verbose:
	$(CC) test -v ./...

test-secp:
	go test -v -run ^TestSecpMessage_sign
	go test -v -run ^TestSecpMessage_digest
.PHONY: deps, test, compile, all
