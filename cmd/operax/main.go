package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"operax/internal/cli"
	"operax/internal/kernelrun"
	"operax/internal/logging"
)

func main() {
	// Initialize logging
	logging.Init()
	logger := logging.GetLogger()

	if handled, err := kernelrun.Dispatch(os.Args[1:]); handled {
		if err != nil {
			logger.Error("kernel dispatch failed", "err", err)
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	dataRoot := os.Getenv("OPERAX_DATA_DIR")
	if dataRoot == "" {
		dataRoot = filepath.Join(".", ".operax")
	}

	app, err := cli.NewApp(dataRoot)
	if err != nil {
		logger.Error("failed to create app", "err", err)
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Set up graceful shutdown on signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)

	ctx, cancel := context.WithCancel(context.Background())
	ctx = logging.WithContext(ctx)

	go func() {
		sig := <-sigChan
		logger.Info("received signal", "signal", sig)
		cancel()
	}()

	if err := app.Run(ctx, os.Args[1:]); err != nil {
		logger.Error("app run failed", "err", err)
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
