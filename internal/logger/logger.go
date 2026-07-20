package logger

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/pkg/errors"
	"github.com/rs/zerolog"

	oidfed "github.com/go-oidfed/lib"
)

// Log is the package-level zerolog.Logger used throughout OFFA. It is the
// single source of truth for internal logging and is configured through Init /
// SetOutput. It is initialised to a sane default (no-color console writer to
// stderr at info level) so it can be used before Init is called, e.g. during
// the initial config load. Call sites that need logrus-style ergonomics may use
// the package-level helper functions (Debug, Info, WithError, ...) below, which
// all operate on Log.
var Log = defaultLogger()

func defaultLogger() zerolog.Logger {
	return zerolog.New(zerolog.ConsoleWriter{
		Out:        os.Stderr,
		NoColor:    true,
		TimeFormat: time.RFC3339,
	}).With().Timestamp().Logger().Level(zerolog.InfoLevel)
}

// LogOutputSettings describes a log destination: optionally a directory holding
// a log file and/or stderr. It mirrors config.LoggerConf but lives here so that
// this package does not depend on the config package (which would create an
// import cycle, as config uses this package for its own logging).
type LogOutputSettings struct {
	Dir    string
	StdErr bool
}

// SmartSettings configures the per-request "smart" logger.
type SmartSettings struct {
	Enabled bool
	Dir     string
}

// InternalLogSettings describes the internal logger configuration.
type InternalLogSettings struct {
	LogOutputSettings
	Level string
	Smart SmartSettings
}

// Settings holds the logger configuration passed in from the application
// (built from config.Config.Logging) via Init / SetOutput.
type Settings struct {
	Access   LogOutputSettings
	Internal InternalLogSettings
}

// settings is the currently active logger configuration, populated by Init /
// SetOutput and read by the smart logger and access logger helpers.
var settings Settings

func mustGetFile(path string) io.Writer {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		panic(err)
	}
	file, err := getFile(path)
	if err != nil {
		panic(err)
	}
	return file
}

func getFile(path string) (io.Writer, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	return f, errors.WithStack(err)
}

var accessLogger *exchangeableWriter
var internalWriter *exchangeableWriter

// MustGetAccessLogger opens the server access logger; on failure the program
// exits. The returned io.Writer is suitable as the output for fiber's logger
// middleware and can be swapped at runtime via MustUpdateAccessLogger (e.g. on
// SIGHUP log file rotation).
func MustGetAccessLogger() io.Writer {
	accessLogger = &exchangeableWriter{
		Writer: mustGetLogWriter(settings.Access, "access.log"),
	}
	return accessLogger
}

// MustUpdateAccessLogger updates the writer of the access logger, e.g. after a
// config reload or log rotation signal.
func MustUpdateAccessLogger() {
	accessLogger.SetOutput(mustGetLogWriter(settings.Access, "access.log"))
}

// exchangeableWriter is an io.Writer whose underlying destination can be
// replaced at runtime without changing the writer identity handed out to
// consumers (e.g. fiber's logger middleware).
type exchangeableWriter struct {
	io.Writer
}

// SetOutput updates the internal writer
func (w *exchangeableWriter) SetOutput(out io.Writer) {
	w.Writer = out
}

func mustGetLogWriter(logConf LogOutputSettings, logfileName string) io.Writer {
	var loggers []io.Writer
	if logConf.StdErr {
		loggers = append(loggers, os.Stderr)
	}
	if logDir := logConf.Dir; logDir != "" {
		loggers = append(loggers, mustGetFile(filepath.Join(logDir, logfileName)))
	}
	switch len(loggers) {
	case 0:
		return io.Discard
	case 1:
		return loggers[0]
	default:
		return io.MultiWriter(loggers...)
	}
}

// parseLogLevel maps the configured internal log level string to a zerolog
// level, defaulting to info on parse errors.
func parseLogLevel(logLevel string) zerolog.Level {
	level, err := zerolog.ParseLevel(logLevel)
	if err != nil {
		// Fall back to a sane default; emit the warning on the soon-to-be
		// configured logger via a temporary one to avoid ordering issues.
		bootstrap := zerolog.New(os.Stderr).With().Timestamp().Logger()
		bootstrap.Warn().
			Str("level", logLevel).Err(err).Msg("unknown log level, falling back to info")
		return zerolog.InfoLevel
	}
	return level
}

// newConsoleWriter builds a no-color zerolog.ConsoleWriter writing to out. This
// keeps log output human readable in files and on stderr, mirroring the
// previous logrus text formatter.
func newConsoleWriter(out io.Writer) zerolog.ConsoleWriter {
	return zerolog.ConsoleWriter{
		Out:        out,
		NoColor:    true,
		TimeFormat: time.RFC3339,
	}
}

// Init initializes the logger from the given settings. It must be called after
// the config has been loaded and before any logging is expected.
func Init(s Settings) {
	zerolog.TimeFieldFormat = time.RFC3339
	settings = s
	internalWriter = &exchangeableWriter{
		Writer: mustGetLogWriter(settings.Internal.LogOutputSettings, "offa.log"),
	}
	SetOutput(s)
}

// SetOutput (re)configures the internal logger output, level, and caller
// reporting based on the given settings. It also routes the go-oidfed library's
// internal logger to the same destination and level so that library logs are
// emitted alongside OFFA's own logs. Safe to call on SIGHUP / config reload.
func SetOutput(s Settings) {
	settings = s
	level := parseLogLevel(s.Internal.Level)
	internalWriter.SetOutput(mustGetLogWriter(s.Internal.LogOutputSettings, "offa.log"))

	console := newConsoleWriter(internalWriter)
	lg := zerolog.New(console).With().Timestamp().Logger()
	if level <= zerolog.DebugLevel {
		lg = lg.With().Caller().Logger()
	}
	lg = lg.Level(level)
	Log = lg
	zerolog.SetGlobalLevel(level)

	// Route the go-oidfed library's internal logger to the same destination and
	// level so its output is consolidated with OFFA's internal logs. The output
	// is wrapped in a console writer so the library's logs are formatted the
	// same way as OFFA's (the library's SetLogOutput replaces the library's own
	// console writer, so we provide one that writes to OFFA's internal writer).
	oidfed.SetLogLevel(level)
	oidfed.SetLogOutput(newConsoleWriter(internalWriter))
}

// Settings returns the currently active logger settings.
func ActiveSettings() Settings { return settings }

// ---------------------------------------------------------------------------
// logrus-compatible facade
//
// The following helpers expose a small, logrus-like API (Debug/Info/WithError/
// WithField/...) backed by the zerolog Log above. They exist so that the rest
// of the codebase can keep using the familiar `log.Debugf`, `log.WithError(err
// ).Error(msg)` ergonomics while being powered by zerolog under the hood. Each
// terminal call constructs a fresh zerolog event, so the returned *FieldLogger
// is safe to reuse for multiple log statements.
// ---------------------------------------------------------------------------

// Fields is the field-map type used by WithFields, mirroring logrus.Fields.
type Fields = map[string]any

// FieldLogger is a logrus.Entry-like handle carrying context (an error and/or
// structured fields) that is applied to every log statement produced through
// its terminal methods.
type FieldLogger struct {
	logger *zerolog.Logger
	err    error
	fields Fields
}

func (f *FieldLogger) event(level zerolog.Level) *zerolog.Event {
	var e *zerolog.Event
	switch level {
	case zerolog.TraceLevel:
		e = f.logger.Trace()
	case zerolog.DebugLevel:
		e = f.logger.Debug()
	case zerolog.InfoLevel:
		e = f.logger.Info()
	case zerolog.WarnLevel:
		e = f.logger.Warn()
	case zerolog.ErrorLevel:
		e = f.logger.Error()
	case zerolog.FatalLevel:
		e = f.logger.Fatal()
	case zerolog.PanicLevel:
		e = f.logger.Panic()
	default:
		e = f.logger.Info()
	}
	if f.err != nil {
		e = e.Err(f.err)
	}
	for k, v := range f.fields {
		e = e.Interface(k, v)
	}
	return e
}

func (f *FieldLogger) sprint(args ...any) string { return fmt.Sprint(args...) }

// Terminal methods (logrus-style, variadic -> fmt.Sprint)
func (f *FieldLogger) Debug(args ...any) { f.event(zerolog.DebugLevel).Msg(f.sprint(args...)) }
func (f *FieldLogger) Info(args ...any)  { f.event(zerolog.InfoLevel).Msg(f.sprint(args...)) }
func (f *FieldLogger) Warn(args ...any)  { f.event(zerolog.WarnLevel).Msg(f.sprint(args...)) }
func (f *FieldLogger) Error(args ...any) { f.event(zerolog.ErrorLevel).Msg(f.sprint(args...)) }
func (f *FieldLogger) Fatal(args ...any) { f.event(zerolog.FatalLevel).Msg(f.sprint(args...)) }

// Formatted variants
func (f *FieldLogger) Debugf(format string, args ...any) {
	f.event(zerolog.DebugLevel).Msgf(format, args...)
}
func (f *FieldLogger) Infof(format string, args ...any) {
	f.event(zerolog.InfoLevel).Msgf(format, args...)
}
func (f *FieldLogger) Warnf(format string, args ...any) {
	f.event(zerolog.WarnLevel).Msgf(format, args...)
}
func (f *FieldLogger) Errorf(format string, args ...any) {
	f.event(zerolog.ErrorLevel).Msgf(format, args...)
}
func (f *FieldLogger) Fatalf(format string, args ...any) {
	f.event(zerolog.FatalLevel).Msgf(format, args...)
}

// WithError returns a FieldLogger that attaches the given error to all
// subsequent log statements, mirroring logrus.WithError.
func WithError(err error) *FieldLogger {
	l := Log
	return &FieldLogger{logger: &l, err: err}
}

// WithField returns a FieldLogger that attaches a single structured field to
// all subsequent log statements, mirroring logrus.WithField.
func WithField(key string, value any) *FieldLogger {
	l := Log
	return &FieldLogger{logger: &l, fields: Fields{key: value}}
}

// WithFields returns a FieldLogger that attaches multiple structured fields to
// all subsequent log statements, mirroring logrus.WithFields.
func WithFields(fields Fields) *FieldLogger {
	l := Log
	return &FieldLogger{logger: &l, fields: fields}
}

// Package-level terminal helpers (operate on Log)
func Debug(args ...any) { Log.Debug().Msg(fmt.Sprint(args...)) }
func Info(args ...any)  { Log.Info().Msg(fmt.Sprint(args...)) }
func Warn(args ...any)  { Log.Warn().Msg(fmt.Sprint(args...)) }
func Error(args ...any) { Log.Error().Msg(fmt.Sprint(args...)) }
func Fatal(args ...any) { Log.Fatal().Msg(fmt.Sprint(args...)) }

// Package-level formatted helpers (operate on Log)
func Debugf(format string, args ...any) { Log.Debug().Msgf(format, args...) }
func Infof(format string, args ...any)  { Log.Info().Msgf(format, args...) }
func Warnf(format string, args ...any)  { Log.Warn().Msgf(format, args...) }
func Errorf(format string, args ...any) { Log.Error().Msgf(format, args...) }
func Fatalf(format string, args ...any) { Log.Fatal().Msgf(format, args...) }
