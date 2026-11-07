package main

import (
	"github.com/nekoskin/whispera/app/client"
	"github.com/nekoskin/whispera/core/tunnel"
)

func main() {
	tunnel.LogCaptureDevices()
	client.RunMain()
}
