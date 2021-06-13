// Copyright (C) 2021 Vojtech Aschenbrenner <v@asch.cz>

package buse

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"sync"
	"syscall"
)

const (
	// Character device for buse device %d and read queue %d.
	buseReadPathFmt = "/dev/buse%d-r%d"

	// Character device for buse device %d and write queue %d.
	buseWritePathFmt = "/dev/buse%d-w%d"

	// Path to the configfs directory.
	configFsPath = "/sys/kernel/config/buse"

	// Size of write request in write queue.
	writeRequestSize = 16

	// Size of read request in read queue.
	readRequestSize = 24
)

// Provides functions which are called by buse as a reaction to the received
// command.
type BuseReadWriter interface {
	// Read extent starting at sector with length lenth. Data should be
	// read to chunk which has appropriate size. Called as a reaction to
	// the read command in the read queue.
	BuseRead(sector, length int64, chunk []byte) error

	// Write batched writes stored in chunk. writes is the number of
	// individual writes in the metadata part of the chunk. Called as a
	// reaction to the batched writes command in the write queue.
	BuseWrite(writes int64, chunk []byte) error

	// Called just before the block device is started.
	BusePreRun()

	// Called after the block device is removed.
	BusePostRemove()
}

// Options for created buse device.
type Options struct {
	Durable        bool
	WriteChunkSize int64
	BlockSize      int64
	Threads        int
	Major          int64
	WriteShmSize   int64
	ReadShmSize    int64
	Size           int64
	CollisionArea  int64
	QueueDepth     int64
	Scheduler      bool
}

// Buse is a library wrapping the low level interaction with buse kernel module
// and provides simple API to for creating a block device in user space.
type Buse struct {
	ReadWriter BuseReadWriter
	Options    Options
}

// Returns new instance of Buse configured with options o.
func New(rw BuseReadWriter, o Options) (Buse, error) {
	buse := Buse{
		ReadWriter: rw,
		Options:    o,
	}

	err := buse.checkOptions()
	if err != nil {
		return Buse{}, err
	}

	err = buse.configure()
	if err != nil {
		return Buse{}, err
	}

	return buse, nil
}

// Returns total memory presented to the system.
func totalMemory() (uint64, error) {
	sysInfo := &syscall.Sysinfo_t{}

	if err := syscall.Sysinfo(sysInfo); err != nil {
		return 0, err
	}

	// On 32-bit architectures the result is uint, hence we need to type it
	// to uint64 to conform with function signature.
	totalMemory := uint64(sysInfo.Totalram) * uint64(sysInfo.Unit)

	return totalMemory, nil
}

// Validates passed options.
func (b *Buse) checkOptions() error {
	o := &b.Options

	if o.Threads == 0 || o.Threads > runtime.NumCPU() {
		o.Threads = runtime.NumCPU()
	}

	totalMem, err := totalMemory()
	if err != nil {
		return errors.New("Cannot read total amount of ram!")
	}

	neededMemory := uint64(o.Threads) * uint64(o.WriteShmSize+o.ReadShmSize)
	if neededMemory > totalMem {
		return errors.New("Not enough memory!")
	}

	if o.WriteShmSize%o.WriteChunkSize != 0 {
		return errors.New("Write buffer size has to be a multiple of chunk size!")
	}

	if o.BlockSize != 512 && o.BlockSize != 4096 {
		return errors.New("Block size has to 512 or 4096!")
	}

	return nil
}

// Performs configuration of the block device which is just being created. It
// configures buse device via configs according to the options passed to the
// New() function. When configuration succeed the device is power on.
func (b *Buse) configure() error {
	var noScheduler int64
	if !b.Options.Scheduler {
		noScheduler = 1
	}

	configFsPath := fmt.Sprint(configFsPath, "/", b.Options.Major)
	if _, err := os.Stat(configFsPath); !os.IsNotExist(err) {
		return errors.New(fmt.Sprintf("Device buse%d already exists!", b.Options.Major))
	}

	if err := os.Mkdir(configFsPath, 0755); err != nil {
		return err
	}

	kernelParams := map[string]int64{
		"size":                b.Options.Size,
		"collision_area_size": int64(b.Options.CollisionArea),
		"read_shm_size":       int64(b.Options.ReadShmSize),
		"write_shm_size":      int64(b.Options.WriteShmSize),
		"write_chunk_size":    int64(b.Options.WriteChunkSize),
		"hw_queues":           int64(b.Options.Threads),
		"blocksize":           int64(b.Options.BlockSize),
		"queue_depth":         int64(b.Options.QueueDepth),
		"no_scheduler":        noScheduler,
	}

	for variable, value := range kernelParams {
		if err := b.setConfig(variable, value); err != nil {
			return err
		}
	}

	if err := b.setConfig("power", 1); err != nil {
		return err
	}

	return nil
}

// Opens control file and mmap it. Returns file and mmapped memory.
func openAndMmapControlFile(chardev string, shm_size int) (*os.File, []byte, error) {
	f, err := os.OpenFile(chardev, os.O_RDWR, 0644)
	if err != nil {
		return nil, nil, err
	}

	shmem, err := syscall.Mmap(int(f.Fd()), 0, shm_size,
		syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		f.Close()
		return nil, nil, err
	}

	return f, shmem, err
}

// Parses request reading from write queue character device.
func (b *Buse) parseWriteRequest(request []byte) ([]byte, uint64, uint64) {
	raw := make([]byte, 8)
	copy(raw, request[:8])
	offset := binary.LittleEndian.Uint64(raw)
	writesLen := binary.LittleEndian.Uint64(request[8:16])

	return raw, offset, writesLen
}

// Parses request reading from read queue character device.
func (b *Buse) parseReadRequest(request []byte) ([]byte, uint64, uint64, uint64) {
	raw := make([]byte, 8)
	copy(raw, request[16:24])
	offset := binary.LittleEndian.Uint64(raw)

	sector := binary.LittleEndian.Uint64(request[:8]) * 512 / uint64(b.Options.BlockSize)
	length := binary.LittleEndian.Uint64(request[8:16]) * 512 / uint64(b.Options.BlockSize)

	return raw, offset, sector, length
}

// True if the request means termination of the device.
func isTermination(offset uint64) bool {
	return offset == ^uint64(0)
}

// True if the request is flush.
func isFlush(offset uint64) bool {
	return offset > (1 << 32)
}

// Infinite loop reading from write queue character device and calling
// BuseWrite() callback provided by calling application. When the BuseWrite()
// returns then the batched write is confirmed to the kernel leading to the
// recycling of the buffer in shared memory.
func (b *Buse) writer(chardev string, wgFunc *sync.WaitGroup, shm_size int) {
	defer wgFunc.Done()

	controlFile, shmem, err := openAndMmapControlFile(chardev, shm_size)
	if err != nil {
		panic(err)
	}
	defer controlFile.Close()
	defer syscall.Munmap(shmem)

	requestBuffer := make([]byte, writeRequestSize)
	wg := sync.WaitGroup{}
	for {
		_, err := controlFile.Read(requestBuffer)
		if err != nil {
			continue
		}

		offsetRaw, offset, writesLen := b.parseWriteRequest(requestBuffer)

		if isTermination(offset) {
			wg.Wait()
			return
		}

		if isFlush(offset) {
			if b.Options.Durable {
				wg.Wait()
			}
			controlFile.Write(offsetRaw)
			continue
		}

		dataRegion := shmem[offset : offset+uint64(b.Options.WriteChunkSize)]
		wg.Add(1)
		go func() {
			defer wg.Done()

			err := b.ReadWriter.BuseWrite(int64(writesLen), dataRegion)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Chunk write (%d writes) failed!\n", writesLen)
				fmt.Fprint(os.Stderr, err)
			}

			n, err := controlFile.Write(offsetRaw)
			if err != nil {
				fmt.Fprint(os.Stderr, "Read ack error, n =", n, "err=", err.Error())
				fmt.Fprint(os.Stderr, err)
			}
		}()
	}
}

// Infinite loop reading from read queue character device and calling
// BuseRead() callback provided by calling application. When the BuseRead()
// returns then the read request is acknowledged to the kernel.
func (b *Buse) reader(chardev string, wgFunc *sync.WaitGroup, shm_size int) {
	defer wgFunc.Done()

	controlFile, shmem, err := openAndMmapControlFile(chardev, shm_size)
	if err != nil {
		panic(err)
	}
	defer controlFile.Close()
	defer syscall.Munmap(shmem)

	requestBuffer := make([]byte, readRequestSize)
	var wg sync.WaitGroup
	for {
		_, err := controlFile.Read(requestBuffer)
		if err != nil {
			continue
		}

		offsetRaw, offset, sector, length := b.parseReadRequest(requestBuffer)

		if isTermination(offset) {
			wg.Wait()
			return
		}

		size := int64(length) * b.Options.BlockSize
		dataRegion := shmem[int64(offset) : int64(offset)+size]

		wg.Add(1)
		go func() {
			defer wg.Done()

			err := b.ReadWriter.BuseRead(int64(sector), int64(length), dataRegion)
			if err != nil {
				fmt.Fprint(os.Stderr, err)
			}

			_, err = controlFile.Write(offsetRaw)
			if err != nil {
				fmt.Fprint(os.Stderr, err)
			}
		}()
	}
}

// Bind all the control queues and start processing read and write commands.
// This is done via multiple readers and writers. One worker per queue.
func (b *Buse) Run() {
	b.ReadWriter.BusePreRun()

	var wg sync.WaitGroup
	wg.Add(int(b.Options.Threads) * 2)
	for i := 0; i < int(b.Options.Threads); i++ {
		w := fmt.Sprintf(buseWritePathFmt, b.Options.Major, i)
		r := fmt.Sprintf(buseReadPathFmt, b.Options.Major, i)

		go b.writer(w, &wg, int(b.Options.WriteShmSize))
		go b.reader(r, &wg, int(b.Options.ReadShmSize))
	}
	wg.Wait()
}

// Write value to configfs variable.
func (b *Buse) setConfig(variable string, value int64) error {
	configFsPath := fmt.Sprint(configFsPath, "/", b.Options.Major, "/", variable)
	byteValue := []byte(fmt.Sprint(value))

	err := ioutil.WriteFile(configFsPath, byteValue, 0644)

	return err
}

// Stop buse device. All requests are refused but the device is still visible
// and can be started again.
func (b *Buse) StopDevice() error {
	err := b.setConfig("power", 0)
	return err
}

// Remove the device. The device is unregistered as block device.
func (b *Buse) RemoveDevice() error {
	err := syscall.Rmdir(fmt.Sprint(configFsPath, "/", b.Options.Major))
	b.ReadWriter.BusePostRemove()
	return err
}
