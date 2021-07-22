CC := go
CFLAGS := build
SHELL := /bin/bash
OUT_DIR := bin
MOD_NAME := keys

default: all

all: deps test compile

deps:
	$(CC) get ./... && $(CC) mod tidy

compile:
	$(CC) $(CFLAGS) ./...

test:
	$(CC) test ./...

.PHONY: deps, test, compile, all
