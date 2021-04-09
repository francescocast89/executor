package main

import (
	"bytes"
	"context"
	"executor/parser"
	"log"
	"os/exec"
	"sync"
	"time"
)

type hostInfo struct {
	macAddr string
	ipAdd   string
}

type completedScanEvent struct {
	result hostInfo
}

type hostDownEvent struct {
	result hostInfo
}

type timeoutEvent struct{}

type genericErrorEvent struct {
	error string
}

func main() {
	ctx, ctxCancel := context.WithCancel(context.Background())
	ch := make(chan interface{})
	scanArgs := []string{"-PR", "-sn", "-n"}
	hostsList := []string{"192.168.3.1", "192.168.3.2"}
	respondingHosts := []hostInfo{}
	var wg sync.WaitGroup
	for _, host := range hostsList {
		wg.Add(1)
		go execCmd("nmap", scanArgs, host, 3600*time.Second, &wg, ch)

	}

	go func() {
		wg.Wait()
		ctxCancel()
	}()
	for isTerminated := false; !isTerminated; {
		select {
		case <-ctx.Done():
			isTerminated = true
		case message := <-ch:
			{
				switch message := message.(type) {
				case completedScanEvent:
					{
						log.Printf("Host %v is up, with mac add %v", message.result.ipAdd, message.result.macAddr)
						respondingHosts = append(respondingHosts, message.result)
					}
				case genericErrorEvent:
					{
						log.Println("Generic error")
					}
				case timeoutEvent:
					{
						log.Println("Timeout expired")
					}
				case hostDownEvent:
					{
						log.Printf("Host %v is down", message.result.ipAdd)
					}
				}
			}
		}
	}
	// now perform the port scan on the respondig hosts
	log.Println(respondingHosts)
}
func getDefaultArgs() []string {
	return []string{"-oX", "-", "--privileged"}
}
func execCmd(prg string, args []string, host string, timeout time.Duration, wg *sync.WaitGroup, ch chan interface{}) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	defer wg.Done()

	var (
		stderr, stdout bytes.Buffer
	)

	path, error := exec.LookPath(prg)
	if error != nil {
		log.Fatalf("unable to find nmap: %v", error)
	}
	args = append(args, getDefaultArgs()...)
	args = append(args, host)
	cmd := exec.CommandContext(ctx, path, args...)

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	error = cmd.Start()
	if error != nil {
		ch <- genericErrorEvent{stderr.String()}
		return
	}

	error = cmd.Wait()

	if ctx.Err() == context.DeadlineExceeded {
		ch <- timeoutEvent{}
		return
	}
	// If there's no context error, we know the command completed
	if error != nil {
		ch <- genericErrorEvent{stderr.String()}
		return
	}
	result, error := parser.Parse(stdout.Bytes())
	if error != nil {
		ch <- genericErrorEvent{"Parsing error"}
	} else {
		for _, h := range result.Host {
			hostAdds := h.Addr
			if hostAdds != nil {
				var macAdd, ipAdd string
				for _, i := range hostAdds {
					if i.AddrType == "ipv4" {
						ipAdd = i.Addr
					}
					if i.AddrType == "mac" {
						macAdd = i.Addr
					}
				}
				ch <- completedScanEvent{hostInfo{macAdd, ipAdd}}
			} else {
				ch <- hostDownEvent{hostInfo{"", host}}
			}
		}
	}

}
