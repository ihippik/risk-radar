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

const funcName = "trace_unlinkat"
const traceGroupSyscalls = "syscalls"
const bpfProgPath = "./ebpf/radar.o"
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

	spec, err := ebpf.LoadCollectionSpec(bpfProgPath)
	if err != nil {
		return fmt.Errorf("failed to load eBPF program: %w", err)
	}

	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("failed to create eBPF collection: %w", err)
	}
	defer collection.Close()

	tracepoint, err := link.Tracepoint(
		traceGroupSyscalls,
		"sys_enter_unlinkat",
		collection.Programs[funcName],
		nil,
	)
	if err != nil {
		return fmt.Errorf("failed to attach tracepoint: %w", err)
	}
	defer tracepoint.Close()

	eventsMap, ok := collection.Maps["events"]
	if !ok {
		return fmt.Errorf("failed to find events map in eBPF collection: %w", err)
	}

	reader, err := perf.NewReader(eventsMap, os.Getpagesize())
	if err != nil {
		return fmt.Errorf("failed to create perf event reader: %w", err)
	}
	defer reader.Close()

	go func() {
		<-ctx.Done()
		reader.Close()
		tracepoint.Close()

		s.log.Info("graceful shutdown")

		os.Exit(0)
	}()

	s.log.Info("waiting for events..")

	for event := range s.parser(ctx, reader) {
		s.log.Info(
			"file deleted",
			slog.Any("pid", event.Pid),
			slog.String("command", string(bytes.Trim(event.Comm[:], "\x00"))),
			slog.String("file", string(bytes.Trim(event.Filename[:], "\x00"))),
		)
	}

	return nil
}

func (s *Service) parser(ctx context.Context, reader *perf.Reader) <-chan coreEvent {
	output := make(chan coreEvent, 10)

	var event coreEvent

	go func(ctx context.Context) {
		for {
			if ctx.Err() != nil {
				s.log.Warn("context canceled")
				close(output)

				return
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
	}(ctx)

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
