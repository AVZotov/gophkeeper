package recordpb

import "log/slog"

const redacted = "[REDACTED]"

// LogValue hides the record in slog output: its name and metadata are
// personal data too.
func (*Record) LogValue() slog.Value { return slog.StringValue(redacted) }

// LogValue hides the login and the password in slog output.
func (*Credentials) LogValue() slog.Value { return slog.StringValue(redacted) }

// LogValue hides the text in slog output.
func (*Text) LogValue() slog.Value { return slog.StringValue(redacted) }

// LogValue hides the file in slog output.
func (*File) LogValue() slog.Value { return slog.StringValue(redacted) }

// LogValue hides the card in slog output.
func (*Card) LogValue() slog.Value { return slog.StringValue(redacted) }
