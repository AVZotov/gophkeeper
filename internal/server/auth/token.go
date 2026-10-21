package auth

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// tokenTTL is how long an access token is valid.
const tokenTTL = 15 * time.Minute

// errInvalidToken means the token is malformed, expired or not signed by
// this server.
var errInvalidToken = errors.New("invalid token")

// issueToken returns an HS256 JWT for the user, valid for [tokenTTL] from
// now.
func issueToken(key []byte, userID int64, now time.Time) (string, error) {
	claims := jwt.RegisteredClaims{
		Subject:   strconv.FormatInt(userID, 10),
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(tokenTTL)),
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
}

// parseToken checks the token signature and expiry and returns the user ID
// and the issue time. Only HS256 is accepted. Returns [errInvalidToken] if
// the token does not pass the checks.
func parseToken(key []byte, token string) (userID int64, issuedAt time.Time, err error) {
	var claims jwt.RegisteredClaims
	_, err = jwt.ParseWithClaims(token, &claims,
		func(*jwt.Token) (any, error) { return key, nil },
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("%w: %w", errInvalidToken, err)
	}
	if claims.IssuedAt == nil {
		return 0, time.Time{}, fmt.Errorf("%w: no issue time", errInvalidToken)
	}
	userID, err = strconv.ParseInt(claims.Subject, 10, 64)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("%w: subject: %w", errInvalidToken, err)
	}
	return userID, claims.IssuedAt.Time, nil
}
