.PHONY: run build test lint check stress up

run:
	go run ./cmd/server

build:
	go build -o bin/server ./cmd/server

test:
	go test -race -count=1 ./...

lint:
	golangci-lint run ./...

check: lint test

stress:
	go run ./cmd/stress

up:
	docker compose up -d postgres
