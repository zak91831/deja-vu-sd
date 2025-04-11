package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

// Logger levels
const (
	LevelDebug = "debug"
	LevelInfo  = "info"
	LevelWarn  = "warn"
	LevelError = "error"
)

// Logger formats
const (
	FormatText = "text"
	FormatJSON = "json"
)

// Logger represents a logger instance
type Logger struct {
	level     string
	format    string
	debugLog  *log.Logger
	infoLog   *log.Logger
	warnLog   *log.Logger
	errorLog  *log.Logger
}

// NewLogger creates a new logger instance
func NewLogger(level, format, filePath string) (*Logger, error) {
	// Validate level
	level = strings.ToLower(level)
	if level != LevelDebug && level != LevelInfo && level != LevelWarn && level != LevelError {
		level = LevelInfo
	}

	// Validate format
	format = strings.ToLower(format)
	if format != FormatText && format != FormatJSON {
		format = FormatText
	}

	// Set output writer
	var writer io.Writer = os.Stdout
	if filePath != "" {
		file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %w", err)
		}
		writer = file
	}

	// Create logger
	logger := &Logger{
		level:  level,
		format: format,
	}

	// Initialize log levels
	prefix := ""
	flag := log.LstdFlags
	
	if format == FormatJSON {
		// JSON format doesn't use prefixes, as the level is included in the JSON
		prefix = ""
		// Don't include date/time in the log message as it will be in the JSON
		flag = 0
	} else {
		// Text format uses prefixes to indicate log level
		prefix = ""
	}

	logger.debugLog = log.New(writer, prefix, flag)
	logger.infoLog = log.New(writer, prefix, flag)
	logger.warnLog = log.New(writer, prefix, flag)
	logger.errorLog = log.New(writer, prefix, flag)

	return logger, nil
}

// formatMessage formats a log message according to the configured format
func (l *Logger) formatMessage(level, message string, args ...interface{}) string {
	// Format the message with the provided arguments
	formattedMessage := fmt.Sprintf(message, args...)

	if l.format == FormatJSON {
		// Simple JSON format
		return fmt.Sprintf(`{"level":"%s","message":"%s","timestamp":"%s"}`, 
			level, 
			escapeJSON(formattedMessage), 
			"")  // Timestamp will be added by the logger
	}

	// Text format
	return fmt.Sprintf("[%s] %s", strings.ToUpper(level), formattedMessage)
}

// escapeJSON escapes special characters in a string for JSON
func escapeJSON(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\t", "\\t")
	return s
}

// Debug logs a debug message
func (l *Logger) Debug(message string, args ...interface{}) {
	if l.level == LevelDebug {
		l.debugLog.Println(l.formatMessage(LevelDebug, message, args...))
	}
}

// Info logs an info message
func (l *Logger) Info(message string, args ...interface{}) {
	if l.level == LevelDebug || l.level == LevelInfo {
		l.infoLog.Println(l.formatMessage(LevelInfo, message, args...))
	}
}

// Warn logs a warning message
func (l *Logger) Warn(message string, args ...interface{}) {
	if l.level == LevelDebug || l.level == LevelInfo || l.level == LevelWarn {
		l.warnLog.Println(l.formatMessage(LevelWarn, message, args...))
	}
}

// Error logs an error message
func (l *Logger) Error(message string, args ...interface{}) {
	l.errorLog.Println(l.formatMessage(LevelError, message, args...))
}
