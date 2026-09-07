//go:build unix

package relay

import (
	"syscall"
	"time"
)

func processCPU() time.Duration {
	var proccess syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &proccess); err != nil {
		return 0
	}
	user := time.Duration(proccess.Utime.Sec)*time.Second + time.Duration(proccess.Utime.Usec)*time.Microsecond
	sys := time.Duration(proccess.Stime.Sec)*time.Second + time.Duration(proccess.Stime.Usec)*time.Microsecond
	return user + sys
}
