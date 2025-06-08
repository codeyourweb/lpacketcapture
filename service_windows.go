//go:build windows

package main

import (
	"log"
	"sync"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
)

type nMonitorService struct{}

func (m *nMonitorService) Execute(args []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {

	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown

	status <- svc.Status{State: svc.StartPending}
	status <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	var (
		wg              sync.WaitGroup
		quitService     chan struct{}
		isServiceActive bool
	)

	startServiceGoroutine := func() {
		if isServiceActive {
			return
		}
		quitService = make(chan struct{})
		wg.Add(1)
		go func() {
			defer wg.Done()
			go networkCaptureRoutine(quitService)
		}()
		isServiceActive = true
	}

	stopServiceGoroutine := func() {
		if !isServiceActive {
			return
		}
		close(quitService)
		wg.Wait()
		isServiceActive = false
	}

	startServiceGoroutine()

serviceLoop:
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				logMessage(LOGLEVEL_INFO, "Shutting down network monitor service.")
				stopServiceGoroutine()
				break serviceLoop
			default:
				log.Printf("Unexpected service control request #%d", c)
			}
		}
	}

	status <- svc.Status{State: svc.StopPending}
	return false, 0
}

func runService(name string, isDebug bool) {
	if isDebug {
		err := debug.Run(name, &nMonitorService{})
		if err != nil {
			log.Fatalln("Error running network monitor in interactive mode:", err)
		}
	} else {
		err := svc.Run(name, &nMonitorService{})
		if err != nil {
			log.Fatalln("Error running network monitor in Service Control mode:", err)
		}
	}
}
