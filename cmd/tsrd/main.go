package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"tsr/internal/config"
	"tsr/internal/dnsx"
	"tsr/internal/engine"
	"tsr/internal/mapstore"
	"tsr/internal/system"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("tsrd: ")

	opts, err := parseArgs(os.Args[1:])
	if err != nil {
		fatal(err)
	}
	if opts.generateConfig != "" {
		if err := config.Generate(opts.generateConfig); err != nil {
			fatal(err)
		}
		return
	}

	rt, err := config.Load(opts.config)
	if err != nil {
		fatal(err)
	}

	setup := system.Setup{
		TUN:       rt.Net.TUN,
		Prefix:    rt.Prefix,
		Gateway:   rt.Gateway,
		DNSListen: rt.DNS.Listen,
		Domains:   domains(rt.Routes, rt.Aliases),
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	store, err := mapstore.New(rt.Prefix, rt.Gateway, rt.Routes, rt.Aliases)
	if err != nil {
		fatal(err)
	}

	eng, err := engine.Start(ctx, rt.Net.TUN, rt.Net.MTU, store)
	if err != nil {
		fatal(err)
	}
	defer eng.Close()

	if err := system.Up(setup); err != nil {
		fatal(err)
	}

	dnsSrv := dnsx.New(rt.DNS.Listen, store)
	if err := dnsSrv.Start(); err != nil {
		fatal(err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := dnsSrv.Shutdown(shutdownCtx); err != nil {
			log.Printf("dns shutdown: %v", err)
		}
	}()
	defer func() {
		if err := system.Down(setup); err != nil {
			log.Printf("cleanup: %v", err)
		}
	}()

	log.Printf("ready")
	<-ctx.Done()
	log.Printf("shutting down")
}

func domains(routes []config.RuntimeRoute, aliases []config.RuntimeAlias) []string {
	out := make([]string, 0, len(routes))
	seen := map[string]struct{}{}
	for _, r := range routes {
		for _, domain := range r.Domains {
			if _, ok := seen[domain]; ok {
				continue
			}
			seen[domain] = struct{}{}
			out = append(out, domain)
		}
	}
	for _, alias := range aliases {
		for _, domain := range alias.Domains {
			if _, ok := seen[domain]; ok {
				continue
			}
			seen[domain] = struct{}{}
			out = append(out, domain)
		}
	}
	return out
}

func fatal(err error) {
	log.Printf("fatal: %v", err)
	os.Exit(1)
}

type options struct {
	config         string
	generateConfig string
}

func parseArgs(args []string) (options, error) {
	opts := options{config: "/etc/tsr/config.toml"}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--config":
			i++
			if i >= len(args) || args[i] == "" {
				return opts, fmt.Errorf("--config requires a path")
			}
			opts.config = args[i]
		case "--generate-config":
			i++
			if i >= len(args) || args[i] == "" {
				return opts, fmt.Errorf("--generate-config requires a path")
			}
			opts.generateConfig = args[i]
		case "--help":
			fmt.Fprint(os.Stdout, usage())
			os.Exit(0)
		default:
			return opts, fmt.Errorf("unknown argument %q\n%s", args[i], usage())
		}
	}
	return opts, nil
}

func usage() string {
	return "usage: tsrd [--config PATH]\n       tsrd --generate-config PATH\n"
}
