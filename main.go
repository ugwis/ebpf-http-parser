//go:build linux
// +build linux

package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/fatih/color"
	"golang.org/x/sys/unix"
)

import "C"

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target native -type dataevent_t bpf kprobe.c -- -I./cilium-ebpf/examples/headers -I /usr/include -I /usr/include/x86_64-linux-gnu


const (
    EVENT_TYPE_CONNECT = iota
    EVENT_TYPE_ACCEPT
    EVENT_TYPE_RECV
    EVENT_TYPE_SEND
    EVENT_TYPE_CLOSE
)

/*type dataEvent struct {
	Type   uint8
	Buf    [1024]byte
	SockFd uint32
}*/

func main() {

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}


	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// SysConnect
	kprobeSysConnect, err := link.Kprobe("sys_connect", objs.KprobeSysConnect)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kprobeSysConnect.Close()

	kretprobeSysConnect, err := link.Kretprobe("sys_connect", objs.KretprobeSysConnect)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kretprobeSysConnect.Close()

	// SysRead
	kprobeSysRead, err := link.Kprobe("sys_read", objs.KprobeSysRead)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kprobeSysRead.Close()

	kretprobeSysRead, err := link.Kretprobe("sys_read", objs.KretprobeSysRead)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kretprobeSysRead.Close()

	// SysRecvfrom
	kprobeSysRecvfrom, err := link.Kprobe("sys_recvfrom", objs.KprobeSysRecvfrom)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kprobeSysRecvfrom.Close()

	kretprobeSysRecvfrom, err := link.Kretprobe("sys_recvfrom", objs.KretprobeSysRecvfrom)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kretprobeSysRecvfrom.Close()

	// SysWrite
	kprobeSysWrite, err := link.Kprobe("sys_write", objs.KprobeSysWrite)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kprobeSysWrite.Close()

	kretprobeSysWrite, err := link.Kretprobe("sys_write", objs.KretprobeSysWrite)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kretprobeSysWrite.Close()

	// SysSendto
	kprobeSysSendto, err := link.Kprobe("sys_sendto", objs.KprobeSysSendto)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kprobeSysSendto.Close()

	kretprobeSysSendto, err := link.Kretprobe("sys_sendto", objs.KretprobeSysSendto)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kretprobeSysSendto.Close()

	// SysClose
	kprobeSysClose, err := link.Kprobe("sys_close", objs.KprobeSysClose)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kprobeSysClose.Close()



	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	rd, err := perf.NewReader(objs.Dataevent, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}
	defer rd.Close()

	go func() {
		// Wait for a signal and close the perf reader,
		// which will interrupt rd.Read() and make the program exit.
		<-stopper
		log.Println("Received signal, exiting program..")

		if err := rd.Close(); err != nil {
			log.Fatalf("closing perf event reader: %s", err)
		}
	}()

	log.Printf("Listening for events..")

	requests := map[uint32]string{}
	responses := map[uint32]string{}
	var event bpfDataeventT
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Printf("reading from perf event reader: %s", err)
			continue
		}

		if record.LostSamples != 0 {
			log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
			continue
		}

		// Parse the perf event entry into a bpfEvent structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing perf event: %s", err)
			continue
		}

		//log.Printf("type: %d", event.Type)
		//log.Printf("sock_fd: %d", event.SockFd)
		//log.Printf("Buf: %s", unix.ByteSliceToString(event.Buf[:]))
		sock_fd := event.SockFd
		payload := unix.ByteSliceToString(event.Buf[:])

		switch event.Type {
			case EVENT_TYPE_CONNECT:
			case EVENT_TYPE_ACCEPT:
			case EVENT_TYPE_SEND:
				_, ok := requests[sock_fd]
				if ok {
					requests[sock_fd] += payload
				} else {
					requests[sock_fd] = payload
				}
			case EVENT_TYPE_RECV:
				_, ok := responses[sock_fd]
				if ok {
					responses[sock_fd] += payload
				} else {
					responses[sock_fd] = payload
				}
			case EVENT_TYPE_CLOSE:
				delete(requests, sock_fd)
				delete(responses, sock_fd)
		}

		req_rd := strings.NewReader(requests[sock_fd])
		req_reader := bufio.NewReader(req_rd)
		req, err := http.ReadRequest(req_reader)
		if err != nil {
			//fmt.Println(err)
			continue
		}
		res_rd := strings.NewReader(responses[sock_fd])
		res_reader := bufio.NewReader(res_rd)
		res, err := http.ReadResponse(res_reader, req)
		if err != nil {
			//fmt.Println(err)
			continue
		}
		code_color := color.New(color.FgWhite, color.BgBlack).SprintFunc()
		switch {
			case res.StatusCode >= 500:
				code_color = color.New(color.FgWhite, color.BgHiRed).SprintFunc()
			case res.StatusCode >= 400:
				code_color = color.New(color.FgWhite, color.BgHiBlue).SprintFunc()
			case res.StatusCode >= 300:
				code_color = color.New(color.FgBlack, color.BgHiWhite).SprintFunc()
			case res.StatusCode >= 200:
				code_color = color.New(color.FgWhite, color.BgHiGreen).SprintFunc()
		}

		fmt.Printf("%s | %s |%-s| %s | %-15s | %-20s\n", time.Now().Format("2006/01/02 03:04:05"), res.Proto, code_color(" " + strconv.Itoa(res.StatusCode) + " "), req.Method, req.Host, req.RequestURI)
		delete(requests, sock_fd)
		delete(responses, sock_fd)
		/*fmt.Println(req.Method)
		fmt.Println(req.Host)
		fmt.Println(req.RemoteAddr)
		fmt.Println(res.Status)
		fmt.Println(res.Close)*/
	}

}
