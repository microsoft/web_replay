package webreplay

import (
	"log"
	"os"
	"time"
)

type Monitor struct {
	resetChan chan struct{}
	duration  time.Duration
	stopChan  chan struct{}
}

func NewMonitor(duration time.Duration) *Monitor {
	return &Monitor{
		resetChan: make(chan struct{}, 1),
		stopChan:  make(chan struct{}),
		duration:  duration,
	}
}

// Begin monitoring
func (m *Monitor) Start() {
	timer := time.NewTimer(m.duration)

	for {
		select {
		case <-m.resetChan:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(m.duration)
		case <-timer.C:
			log.Printf("No traffic for %v. Shutting down", m.duration)
			os.Exit(0)
		case <-m.stopChan:
			timer.Stop()
			return
		}
	}
}

// Reset monitor
func (m *Monitor) Reset() {
	select {
	case m.resetChan <- struct{}{}:
	default:
	}
}

// Stop monitor
func (m *Monitor) Stop() {
	close(m.stopChan)
}
