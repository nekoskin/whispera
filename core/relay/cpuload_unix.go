//go:build unix

package relay

import (
	"syscall"
	"time"
)

func processCPU() time.Duration {
	var process syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &process); err != nil {
		return 0
	}
	user := time.Duration(process.Utime.Sec)*time.Second + time.Duration(process.Utime.Usec)*time.Microsecond
	sys := time.Duration(process.Stime.Sec)*time.Second + time.Duration(process.Stime.Usec)*time.Microsecond
	return user + sys
}
