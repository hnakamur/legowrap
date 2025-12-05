package main

import (
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"time"
)

type LogConfig struct {
	FilenamePattern string `yaml:"filename_pattern"`
	Level           string `yaml:"level"`
}

func openLogFile(cfg *LogConfig, now time.Time) (*os.File, error) {
	switch cfg.FilenamePattern {
	case "stdout", "/dev/stdout":
		return os.Stdout, nil
	case "stderr", "/dev/stderr":
		return os.Stderr, nil
	default:
		filename := now.Format(cfg.FilenamePattern)
		return os.Create(filename)
	}
}

func cleanLogFile(file *os.File) error {
	if file == os.Stdout || file == os.Stderr {
		return nil
	}
	return file.Close()
}

func setupSlogDefaultLogger(w io.Writer, level string) error {
	lvl, err := parseSlogLogLevel(level)
	if err != nil {
		return err
	}
	var programLevel = new(slog.LevelVar)
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level: programLevel,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			_ = groups
			if a.Key == slog.TimeKey {
				if t, ok := a.Value.Any().(time.Time); ok {
					// format timestamp with millisecond precision
					a.Value = slog.StringValue(t.Format("2006-01-02T15:04:05.000000"))
				}
			}
			return a
		},
	})
	slog.SetDefault(slog.New(h))
	programLevel.Set(lvl)
	return nil
}

func parseSlogLogLevel(level string) (slog.Level, error) {
	switch level {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.Level(math.MinInt),
			fmt.Errorf("unsupported slog level: %s", level)
	}
}
