package main

import (
	"context"
	"os"
	"os/signal"
	"pam-loadtest/internal/app"
	"syscall"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	os.Exit(app.RunContext(ctx, os.Args[1:], os.Stdout, os.Stderr))
}
