package gophkeeperv1

import "log/slog"

const redacted = "[REDACTED]"

// LogValue hides the login key and the envelope in slog output: with them
// one can guess the password offline.
func (*RegisterRequest) LogValue() slog.Value { return slog.StringValue(redacted) }

// LogValue hides the login key in slog output.
func (*LoginRequest) LogValue() slog.Value { return slog.StringValue(redacted) }

// LogValue hides the token and the envelope in slog output.
func (*LoginResponse) LogValue() slog.Value { return slog.StringValue(redacted) }

// LogValue hides the login keys and the envelope in slog output.
func (*ChangePasswordRequest) LogValue() slog.Value { return slog.StringValue(redacted) }
