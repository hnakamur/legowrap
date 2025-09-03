package legowrap

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/go-acme/lego/v4/log"
)

type SlogLeveledLogger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

var _ SlogLeveledLogger = (*slog.Logger)(nil)

type LegoSlogAdapter struct {
	wrapped SlogLeveledLogger
}

func NewLegoSlogAdapter(wrapped SlogLeveledLogger) *LegoSlogAdapter {
	return &LegoSlogAdapter{wrapped: wrapped}
}

var _ log.StdLogger = (*LegoSlogAdapter)(nil)

func (l *LegoSlogAdapter) Fatal(args ...any) {
	l.wrapped.Error(fmt.Sprint(args...))
	os.Exit(1)
}

func (l *LegoSlogAdapter) Fatalln(args ...any) {
	l.wrapped.Error(fmt.Sprint(args...))
	os.Exit(1)
}

func (l *LegoSlogAdapter) Fatalf(format string, args ...any) {
	l.wrapped.Error(fmt.Sprintf(format, args...))
	os.Exit(1)
}

func (l *LegoSlogAdapter) Print(args ...any) {
	l.wrapped.Error(fmt.Sprint(args...))
}

func (l *LegoSlogAdapter) Println(args ...any) {
	l.wrapped.Error(fmt.Sprint(args...))
}

func (l *LegoSlogAdapter) Printf(format string, args ...any) {
	const (
		infoPrefix = "[INFO] "
		warnPrefix = "[WARN] "
	)
	if after, ok := strings.CutPrefix(format, infoPrefix); ok {
		l.wrapped.Info(fmt.Sprintf(after, args...))
	} else if after, ok = strings.CutPrefix(format, warnPrefix); ok {
		l.wrapped.Warn(fmt.Sprintf(after, args...))
	} else {
		l.wrapped.Error(fmt.Sprintf(format, args...))
	}
}
