package engine

import (
	"context"
	"log"

	"github.com/xjasonlyu/tun2socks/v2/core"
	"github.com/xjasonlyu/tun2socks/v2/core/device"
	"github.com/xjasonlyu/tun2socks/v2/core/device/tun"
	tunlog "github.com/xjasonlyu/tun2socks/v2/log"
	"github.com/xjasonlyu/tun2socks/v2/tunnel"
	"github.com/xjasonlyu/tun2socks/v2/tunnel/statistic"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"github.com/exilens/xns-resolver/internal/mapstore"
	"github.com/exilens/xns-resolver/internal/netdial"
)

type Engine struct {
	device device.Device
	stack  *stack.Stack
	tun    *tunnel.Tunnel
}

func Start(_ context.Context, name string, mtu uint32, store *mapstore.Store, transport netdial.Transport) (*Engine, error) {
	tunlog.SetLogger(tunlog.Must(tunlog.NewLeveled(tunlog.SilentLevel)))

	dev, err := tun.Open(name, mtu)
	if err != nil {
		return nil, err
	}
	t := tunnel.New(netdial.New(store, transport), statistic.DefaultManager)
	st, err := core.CreateStack(&core.Config{
		LinkEndpoint:     dev,
		TransportHandler: t,
	})
	if err != nil {
		dev.Close()
		return nil, err
	}
	t.ProcessAsync()
	log.Printf("tun netstack ready: %s/%s", dev.Type(), dev.Name())
	return &Engine{device: dev, stack: st, tun: t}, nil
}

func (e *Engine) Close() {
	if e == nil {
		return
	}
	if e.tun != nil {
		e.tun.Close()
	}
	if e.device != nil {
		e.device.Close()
	}
	if e.stack != nil {
		e.stack.Close()
		e.stack.Wait()
	}
}
