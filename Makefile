CC := go
CFLAGS := build
SHELL := /bin/bash
OUT_DIR := bin
MOD_NAME := keys

default: all

all: deps test compile
verb: deps test-verbose compile
secp: deps test-secp compile

deps:
	$(CC) get ./... && $(CC) mod tidy

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
