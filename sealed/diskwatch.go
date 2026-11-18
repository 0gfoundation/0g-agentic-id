package main

import (
	"context"
	"fmt"
	"time"

	"seal-verify/internal/logger"
	"seal-verify/internal/servicehost"
)

// The sandbox disk. sealed, the agent and the programs it hosts share one
// filesystem with no quota inside it: the agent's files, its file inbox and
// outbox, logs and caches all draw on the same space. The disk watch reads
// the free space of the filesystem that holds the agent's home every
// diskCheckInterval and, while it is low, reports a "warning" that names the
// free space and what the owner can do.
//
// Low is servicehost's reserve: under DiskReserveBytes (1 GiB) or, where the
// filesystem counts them, DiskReserveInodes free. Below it sealed stops every
// hosted service process and refuses new ones, so the owner hears about the
// disk when the agent starts losing what it runs, not after. The warning
// clears only once free space is back diskClearMarginBytes (and
// diskClearMarginInodes) above that line, so files written and removed
// around it do not raise and clear it every minute. Only those two crossings
// send a report at once; the free figure in between reaches the attestor
// with the next heartbeat.

const (
	diskCheckInterval     = time.Minute
	diskClearMarginBytes  = 512 << 20
	diskClearMarginInodes = 32768
	diskLowAdvice         = "ask the agent to delete files it no longer needs, or reset it"
)

// diskWatch keeps status's disk warning current from free-space readings of
// the filesystem holding path. One goroutine owns it (run).
type diskWatch struct {
	path   string
	read   func(path string) (servicehost.FreeSpace, error)
	status *runtimeStatus
	report func()
	low    bool
}

func newDiskWatch(path string, report func()) *diskWatch {
	return &diskWatch{path: path, read: servicehost.ReadFreeSpace, status: currentStatus, report: report}
}

// run checks every diskCheckInterval until ctx ends.
func (d *diskWatch) run(ctx context.Context) {
	t := time.NewTicker(diskCheckInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.check()
		}
	}
}

// check takes one reading, sets the disk warning ("" when the disk has
// room), and reports when the warning rose or cleared.
func (d *diskWatch) check() {
	free, err := d.read(d.path)
	if err != nil {
		// Unreadable is not full: the warning stays as it was.
		logger.Once("diskwatch.read", "WARN disk watch: cannot read the free space of %s: %v", d.path, err)
		return
	}
	message := d.next(free)
	d.status.DiskIssue(message)
	if (message != "") == d.low {
		return
	}
	d.low = message != ""
	if d.low {
		logger.Logf("WARN %s", message)
	} else {
		logger.Logf("OK   sandbox disk has room again: %d MiB free", free.Bytes>>20)
	}
	d.report()
}

// next is the warning for one reading, given whether the disk was low
// before it.
func (d *diskWatch) next(free servicehost.FreeSpace) string {
	bytesLine, inodesLine := int64(servicehost.DiskReserveBytes), int64(servicehost.DiskReserveInodes)
	if d.low {
		bytesLine += diskClearMarginBytes
		inodesLine += diskClearMarginInodes
	}
	switch {
	case free.Bytes < bytesLine:
		return fmt.Sprintf("sandbox disk nearly full: %d MiB free; %s", free.Bytes>>20, diskLowAdvice)
	case free.Inodes >= 0 && free.Inodes < inodesLine:
		return fmt.Sprintf("sandbox disk nearly full: room for %d more files; %s", free.Inodes, diskLowAdvice)
	}
	return ""
}
