# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Go module: `example.com/pulse/pulse` (Go 1.25.3)

This project is in early development — only `go.mod` exists so far.

## Common Commands

```bash
go build ./...        # Build all packages
go test ./...         # Run all tests
go test ./... -run TestFoo  # Run a specific test
go vet ./...          # Static analysis
```
