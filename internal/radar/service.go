package radar

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"
)

type repository interface {
	SaveEvents(e []*Event) error
}

type Service struct {
	log  *slog.Logger
	repo repository
}

const bpfProgPath = "./radar.o"
const memLockLimit = 64 * 1024 * 1024 // 64 MiB

func NewService(log *slog.Logger, repo repository) *Service {
	return &Service{
		log:  log,
		repo: repo,
	}
}

func (s *Service) Start(ctx context.Context) error {
	if err := s.init(ctx); err != nil {
		return fmt.Errorf("init: %w", err)
	}

	// Load the compiled eBPF program from ELF
	spec, err := ebpf.LoadCollectionSpec(bpfProgPath)
	if err != nil {
		return fmt.Errorf("failed to load eBPF program: %w", err)
	}

	// Create a new eBPF Collection
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("failed to create eBPF collection: %w", err)
	}
	defer collection.Close()

	// Attach the eBPF program to a tracepoint
	tracepoint, err := link.Tracepoint(
		"syscalls",
		"sys_enter_unlinkat",
		collection.Programs["trace_unlinkat"],
		nil,
	)
	if err != nil {
		return fmt.Errorf("failed to attach tracepoint: %w", err)
	}
	defer tracepoint.Close()

	// Set up a perf event reader to read the output from the eBPF program
	eventsMap, ok := collection.Maps["events"]
	if !ok {
		return fmt.Errorf("failed to find events map in eBPF collection: %w", err)
	}

	reader, err := perf.NewReader(eventsMap, os.Getpagesize())
	if err != nil {
		return fmt.Errorf("failed to create perf event reader: %w", err)
	}
	defer reader.Close()

	// Goroutine to handle graceful shutdown on receiving a signal
	go func() {
		<-ctx.Done()
		reader.Close()
		tracepoint.Close()

		s.log.Info("graceful shutdown")

		os.Exit(0)
	}()

	for event := range s.parser(ctx, reader) {
		s.log.Info(
			"file deleted",
			slog.Any("pid", event.Pid),
			slog.String("command", string(event.Comm[:])),
			slog.String("file", string(event.Filename[:])),
		)
	}

	return nil
}

func (s *Service) parser(ctx context.Context, reader *perf.Reader) <-chan coreEvent {
	output := make(chan coreEvent, 10)
	defer close(output)

	var event coreEvent

	for {
		if ctx.Err() != nil {
			return output
		}

		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				break
			}

			s.log.Error("failed to read from perf event reader", "error", err)

			continue
		}

		if err = binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			s.log.Error("failed to decode perf event", "error", err)

			continue
		}

		output <- event
	}

	return output
}

func (s *Service) init(_ context.Context) error {
	// Set the RLIMIT_MEMLOCK resource limit
	var rLimit unix.Rlimit

	rLimit.Cur = memLockLimit
	rLimit.Max = memLockLimit

	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &rLimit); err != nil {
		return fmt.Errorf("failed to set rlimit: %w", err)
	}

	return nil
}
