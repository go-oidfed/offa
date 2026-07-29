package logger

import (
	"io"
	"path/filepath"
	"sync"

	"github.com/gofiber/fiber/v2"
	"github.com/rs/zerolog"
)

// smartLogger is a per-request zerolog.Logger that writes to the regular
// internal log destination (so smart entries still appear in offa.log) and,
// additionally, buffers every entry until an error-level entry is emitted.
//
// When an error is logged, the buffer is flushed to a dedicated per-request
// file (named after the request id) and all subsequent entries for that request
// are written directly to that file. If no error occurs for the request, the
// per-request file is never created. This reproduces the behaviour of the
// previous logrus-based "smart logger" using zerolog's TriggerLevelWriter.

// newSmartLogger builds a smart logger for the given request id. The logger
// emits to the regular internal log destination immediately and additionally
// buffers entries until an error triggers a flush to the per-request file.
func newSmartLogger(id string) zerolog.Logger {
	lazyFile := &lazyFileWriter{
		dir: settings.Internal.Smart.Dir,
		id:  id,
	}
	// The per-request file receives pretty (console) formatted output, matching
	// the regular internal log format.
	perRequestWriter := newConsoleWriter(lazyFile)

	trigger := &zerolog.TriggerLevelWriter{
		Writer:           perRequestWriter,
		ConditionalLevel: zerolog.WarnLevel,  // buffer everything up to warn ...
		TriggerLevel:     zerolog.ErrorLevel, // ... until an error is logged
	}

	// The smart logger writes to both the regular internal destination (so
	// smart entries show up in offa.log) and the triggering per-request writer.
	// Both destinations are wrapped in a console writer so the format matches
	// the regular internal logger output.
	multi := zerolog.MultiLevelWriter(newConsoleWriter(internalWriter), trigger)
	lg := zerolog.New(multi).With().Timestamp().Logger()
	if zerolog.GlobalLevel() <= zerolog.DebugLevel {
		lg = lg.With().Caller().Logger()
	}
	lg = lg.Level(zerolog.GlobalLevel())
	if id != "" {
		lg = lg.With().Str("requestid", id).Logger()
	}
	return lg
}

// GetRequestLogger returns a *zerolog.Logger scoped to the given request id.
//
// When smart logging is disabled (the default), the returned logger simply
// attaches the request id to the regular internal logger. When smart logging is
// enabled, the returned logger additionally buffers all entries for the request
// and flushes them to a dedicated per-request file the first time an error is
// logged for that request; if no error occurs, no per-request file is created.
func GetRequestLogger(ctx *fiber.Ctx) *zerolog.Logger {
	rid, _ := ctx.Locals("requestid").(string)
	return getIDLogger(rid)
}

// GetSSHRequestLogger returns a *zerolog.Logger scoped to the given SSH session
// id, with the same smart-logging semantics as GetRequestLogger.
func GetSSHRequestLogger(sessionID string) *zerolog.Logger {
	return getIDLogger(sessionID)
}

func getIDLogger(id string) *zerolog.Logger {
	if !settings.Internal.Smart.Enabled {
		return new(Log.With().Str("requestid", id).Logger())
	}
	return new(newSmartLogger(id))
}

// lazyFileWriter opens its target file on first Write so that per-request error
// log files are only created when an error actually occurs.
type lazyFileWriter struct {
	dir  string
	id   string
	once sync.Once
	file io.Writer
	err  error
}

func (w *lazyFileWriter) Write(p []byte) (int, error) {
	w.once.Do(
		func() {
			f, err := getFile(filepath.Join(w.dir, w.id))
			if err != nil {
				w.err = err
				return
			}
			w.file = f
		},
	)
	if w.err != nil {
		return 0, w.err
	}
	return w.file.Write(p)
}
