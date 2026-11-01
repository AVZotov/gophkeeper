package cli

import (
	"context"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"net"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"

	pb "github.com/AVZotov/gophkeeper/api/gophkeeper/v1"
	"github.com/AVZotov/gophkeeper/internal/client/recordpb"
	"github.com/AVZotov/gophkeeper/internal/client/remote"
	"github.com/AVZotov/gophkeeper/internal/client/session"
	"github.com/AVZotov/gophkeeper/internal/client/storage"
	"github.com/AVZotov/gophkeeper/internal/client/vaultcrypto"
	"github.com/AVZotov/gophkeeper/internal/client/vaultsync"
	"github.com/AVZotov/gophkeeper/internal/pgtest"
	"github.com/AVZotov/gophkeeper/internal/server/auth"
	"github.com/AVZotov/gophkeeper/internal/server/rpcserver"
	serverstorage "github.com/AVZotov/gophkeeper/internal/server/storage"
	"github.com/AVZotov/gophkeeper/internal/server/vault"
	"github.com/AVZotov/gophkeeper/internal/tlstest"
)

// bufSize is the buffer of the in-memory connection.
const bufSize = 1 << 20

// testServerAddress is the address the clients log in to. The connection
// goes to the in-memory listener; the address gives the TLS server name.
const testServerAddress = "localhost:8443"

// Passwords of the test users.
const (
	firstPassword  = "first password"
	secondPassword = "second password"
)

// testDSN points to one PostgreSQL container shared by all tests of the
// package.
var testDSN string

func TestMain(m *testing.M) {
	code, err := runTests(m)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(code)
}

// runTests starts the container, runs the tests and removes the container.
func runTests(m *testing.M) (int, error) {
	dsn, stop, err := pgtest.Start(context.Background())
	if err != nil {
		return 0, err
	}
	defer func() {
		if err := stop(); err != nil {
			fmt.Fprintln(os.Stderr, "remove container:", err)
		}
	}()
	testDSN = dsn
	return m.Run(), nil
}

// testServer is the real server with the test database, serving on an
// in-memory listener.
type testServer struct {
	srv    *grpc.Server
	lis    *bufconn.Listener
	ca     string
	secret []byte
}

func startServer(t *testing.T) *testServer {
	t.Helper()
	cert := tlstest.New(t)
	store, err := serverstorage.Open(t.Context(), testDSN)
	require.NoError(t, err)
	t.Cleanup(store.Close)
	log := slog.New(slog.DiscardHandler)
	secret := make([]byte, auth.SecretSize)
	rand.Read(secret)
	authSvc, err := auth.NewService(store, secret, log)
	require.NoError(t, err)

	s := &testServer{
		srv:    rpcserver.New(cert.TLS, authSvc, vault.NewService(store, log)),
		lis:    bufconn.Listen(bufSize),
		ca:     cert.CertFile,
		secret: secret,
	}
	go s.srv.Serve(s.lis)
	t.Cleanup(s.srv.Stop)
	return s
}

// dialOptions connect a client to the in-memory listener.
func (s *testServer) dialOptions() []grpc.DialOption {
	return []grpc.DialOption{grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
		return s.lis.DialContext(ctx)
	})}
}

// testClient is one device: a client directory and the session key printed
// to it.
type testClient struct {
	t   *testing.T
	app app
	key string
}

func (s *testServer) newClient(t *testing.T) *testClient {
	a := testApp(t)
	a.dialOptions = s.dialOptions()
	return &testClient{t: t, app: a}
}

// run runs gophkeeper with args and the session key of c in the
// environment.
func (c *testClient) run(stdin string, args ...string) (string, error) {
	c.t.Helper()
	c.t.Setenv(sessionEnv, c.key)
	stdout, _, err := run(c.t, c.app, stdin, args...)
	return stdout, err
}

// enter runs a command that prints a session key with --raw and keeps the
// key.
func (c *testClient) enter(stdin string, args ...string) {
	c.t.Helper()
	stdout, err := c.run(stdin, append(args, "--raw")...)
	require.NoError(c.t, err)
	c.key = strings.TrimSpace(stdout)
}

func (c *testClient) register(s *testServer, login, password string) {
	c.t.Helper()
	c.enter(password+"\n"+password+"\n", "register", login, "--server", testServerAddress, "--ca", s.ca)
}

func (c *testClient) login(s *testServer, login, password string) {
	c.t.Helper()
	c.enter(password+"\n", "login", login, "--server", testServerAddress, "--ca", s.ca)
}

func (c *testClient) unlock(password string) {
	c.t.Helper()
	c.enter(password+"\n", "unlock")
}

func (c *testClient) sync() string {
	c.t.Helper()
	stdout, err := c.run("", "sync")
	require.NoError(c.t, err)
	return stdout
}

// store opens the local database of c.
func (c *testClient) store() *storage.Store {
	c.t.Helper()
	store, err := c.app.openStore(c.t.Context())
	require.NoError(c.t, err)
	c.t.Cleanup(func() { store.Close() })
	return store
}

func (c *testClient) state() storage.State {
	c.t.Helper()
	st, err := c.store().State(c.t.Context())
	require.NoError(c.t, err)
	return st
}

func (c *testClient) keys() session.Keys {
	c.t.Helper()
	keys, err := session.Load(sessionPath(c.t, c.app), c.key, time.Now())
	require.NoError(c.t, err)
	return keys
}

// save saves a local change of the record with the given ID, as the record
// commands do.
func (c *testClient) save(id uuid.UUID, name string) {
	c.t.Helper()
	c.saveContent(id, name, "content of "+name)
}

func (c *testClient) saveContent(id uuid.UUID, name, content string) {
	c.t.Helper()
	plain, err := proto.Marshal(recordpb.Record_builder{
		Name: name,
		Text: recordpb.Text_builder{Content: content}.Build(),
	}.Build())
	require.NoError(c.t, err)
	ciphertext := vaultcrypto.EncryptRecord(c.keys().Data, id, plain)
	require.NoError(c.t, c.store().SaveLocal(c.t.Context(), id, false, ciphertext))
}

func (c *testClient) add(name string) uuid.UUID {
	id := uuid.New()
	c.save(id, name)
	return id
}

func (c *testClient) delete(id uuid.UUID) {
	c.t.Helper()
	require.NoError(c.t, c.store().SaveLocal(c.t.Context(), id, true, nil))
}

// names returns the sorted names of the live local records.
func (c *testClient) names() []string {
	c.t.Helper()
	records, err := c.store().List(c.t.Context())
	require.NoError(c.t, err)
	key := c.keys().Data
	names := []string{}
	for _, r := range records {
		plain, err := vaultcrypto.DecryptRecord(key, r.ID, r.Ciphertext)
		require.NoError(c.t, err)
		var rec recordpb.Record
		require.NoError(c.t, proto.Unmarshal(plain, &rec))
		names = append(names, rec.GetName())
	}
	slices.Sort(names)
	return names
}

func (c *testClient) dirty() []storage.Record {
	c.t.Helper()
	dirty, err := c.store().Dirty(c.t.Context())
	require.NoError(c.t, err)
	return dirty
}

func newLogin() string {
	return "alice-" + rand.Text()
}

// twoDevices registers a user on a and logs in as the same user on b.
func twoDevices(t *testing.T) (s *testServer, a, b *testClient) {
	t.Helper()
	s = startServer(t)
	a, b = s.newClient(t), s.newClient(t)
	login := newLogin()
	a.register(s, login, firstPassword)
	b.login(s, login, firstPassword)
	return s, a, b
}

func TestSyncTwoDevices(t *testing.T) {
	_, a, b := twoDevices(t)
	assert.Equal(t, a.keys().Data, b.keys().Data, "one data key for the user")

	id := a.add("mail")
	assert.Equal(t, "Pushed 1, pulled 1, conflicts 0.\n", a.sync())
	assert.Equal(t, "Pushed 0, pulled 1, conflicts 0.\n", b.sync())
	assert.Equal(t, []string{"mail"}, b.names())

	b.save(id, "mail v2")
	b.sync()
	a.sync()
	assert.Equal(t, []string{"mail v2"}, a.names())

	a.delete(id)
	a.sync()
	b.sync()
	assert.Empty(t, b.names())
	assert.Empty(t, a.dirty())
	assert.Empty(t, b.dirty())
	assert.Equal(t, a.state().LastRevision, b.state().LastRevision)
}

func TestSyncPullsPages(t *testing.T) {
	_, a, b := twoDevices(t)
	// Two records that do not fit into one page together.
	large := strings.Repeat("x", pb.MaxPageBytes*3/4)
	a.saveContent(uuid.New(), "first", large)
	a.saveContent(uuid.New(), "second", large)
	a.sync()

	assert.Equal(t, "Pushed 0, pulled 2, conflicts 0.\n", b.sync())
	assert.Equal(t, []string{"first", "second"}, b.names())
	assert.Equal(t, a.state().LastRevision, b.state().LastRevision)
}

func TestSyncConflicts(t *testing.T) {
	tests := []struct {
		name string
		// theirs and ours change the record on b, which syncs first, and on a.
		theirs, ours func(c *testClient, id uuid.UUID)
		want         []string
		wantOutput   string
	}{
		{
			name:       "our delete against their change",
			theirs:     func(c *testClient, id uuid.UUID) { c.save(id, "note by b") },
			ours:       (*testClient).delete,
			want:       []string{"note by b"},
			wantOutput: "Pushed 0, pulled 1, conflicts 0.\n",
		},
		{
			name:       "our change against their delete",
			theirs:     (*testClient).delete,
			ours:       func(c *testClient, id uuid.UUID) { c.save(id, "note by a") },
			want:       []string{"note by a"},
			wantOutput: "Pushed 1, pulled 1, conflicts 0.\n",
		},
		{
			name:       "both change",
			theirs:     func(c *testClient, id uuid.UUID) { c.save(id, "note by b") },
			ours:       func(c *testClient, id uuid.UUID) { c.save(id, "note by a") },
			want:       []string{"note by a" + vaultsync.ConflictSuffix, "note by b"},
			wantOutput: "Pushed 1, pulled 2, conflicts 1.\n",
		},
		{
			name:       "both delete",
			theirs:     (*testClient).delete,
			ours:       (*testClient).delete,
			want:       []string{},
			wantOutput: "Pushed 1, pulled 1, conflicts 0.\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, a, b := twoDevices(t)
			id := a.add("note")
			a.sync()
			b.sync()

			tt.theirs(b, id)
			b.sync()
			tt.ours(a, id)

			assert.Equal(t, tt.wantOutput, a.sync())
			assert.Equal(t, tt.want, a.names())
			assert.Empty(t, a.dirty())
			b.sync()
			assert.Equal(t, tt.want, b.names(), "both devices agree")
		})
	}
}

// TestSyncLostPushResponse pushes a change behind the client's back, as if
// the server accepted the push but its answer was lost.
func TestSyncLostPushResponse(t *testing.T) {
	s, a, b := twoDevices(t)
	id := a.add("note")
	local, err := a.store().Get(t.Context(), id)
	require.NoError(t, err)

	st := a.state()
	client, err := remote.Dial(testServerAddress, s.ca, s.dialOptions()...)
	require.NoError(t, err)
	defer client.Close()
	client.Resume(st.Login, a.keys().Login, st.Token)
	revision, err := client.Push(t.Context(), local)
	require.NoError(t, err)

	assert.Equal(t, "Pushed 1, pulled 1, conflicts 0.\n", a.sync(), "the same bytes are not a conflict")
	got, err := a.store().Get(t.Context(), id)
	require.NoError(t, err)
	assert.Equal(t, storage.Record{ID: id, Revision: revision, Ciphertext: local.Ciphertext}, got)
	b.sync()
	assert.Equal(t, []string{"note"}, b.names(), "no copy on the server")
}

func TestChangePassword(t *testing.T) {
	_, a, b := twoDevices(t)
	a.add("note")
	a.sync()
	oldSalt := a.state().Salt

	_, err := a.run("wrong\n"+secondPassword+"\n"+secondPassword+"\n", "change-password")
	require.ErrorIs(t, err, vaultcrypto.ErrWrongPassword, "wrong current password")

	// A token issued in the second of the change still works, so the token
	// of b has to be older.
	waitNextSecond()
	stdout, err := a.run(firstPassword+"\n"+secondPassword+"\n"+secondPassword+"\n", "change-password")
	require.NoError(t, err)
	assert.Equal(t, "Your master password is changed.\n", stdout)
	assert.NotEqual(t, oldSalt, a.state().Salt)
	a.add("after change")
	assert.Equal(t, "Pushed 1, pulled 1, conflicts 0.\n", a.sync(), "the session goes on with the same key")
	a.unlock(secondPassword)

	_, err = b.run("", "sync")
	require.ErrorIs(t, err, remote.ErrPasswordChanged, "the old login key of b no longer works")

	b.unlock(secondPassword)
	assert.Equal(t, a.state().Salt, b.state().Salt, "unlock took the new salt from the server")
	assert.Equal(t, a.state().Envelope, b.state().Envelope)
	b.sync()
	assert.Equal(t, []string{"after change", "note"}, b.names())
}

// waitNextSecond sleeps past the next whole second. Token issue times have
// whole seconds, so a token issued before the wait is older than a password
// change after it.
func waitNextSecond() {
	const margin = 100 * time.Millisecond
	time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(time.Second + margin)))
}

func TestChangePasswordMismatch(t *testing.T) {
	s := startServer(t)
	a := s.newClient(t)
	a.register(s, newLogin(), firstPassword)

	_, err := a.run(firstPassword+"\n"+secondPassword+"\ntypo\n", "change-password")
	assert.ErrorIs(t, err, errPasswordMismatch)
}

// TestSyncExpiredToken gives the client a token that expired, signed by the
// server, as one saved some time ago.
func TestSyncExpiredToken(t *testing.T) {
	s := startServer(t)
	a := s.newClient(t)
	login := newLogin()
	a.register(s, login, firstPassword)
	a.add("note")

	expired := expiredToken(t, s, a.state().Token)
	require.NoError(t, a.store().UpdateState(t.Context(), func(st *storage.State) { st.Token = expired }))
	client, err := remote.Dial(testServerAddress, s.ca, s.dialOptions()...)
	require.NoError(t, err)
	defer client.Close()
	client.Resume(login, vaultcrypto.LoginKey{}, expired)
	_, _, err = client.Pull(t.Context(), 0)
	require.ErrorIs(t, err, remote.ErrWrongCredentials, "the server rejects the expired token")

	assert.Equal(t, "Pushed 1, pulled 1, conflicts 0.\n", a.sync())
	assert.NotEqual(t, expired, a.state().Token, "the token of the silent login is saved")
}

// expiredToken returns a token for the user of token that expired a minute
// ago. The key derivation repeats the one of the server.
func expiredToken(t *testing.T, s *testServer, token string) string {
	t.Helper()
	var claims jwt.RegisteredClaims
	_, _, err := jwt.NewParser().ParseUnverified(token, &claims)
	require.NoError(t, err)
	key, err := hkdf.Expand(sha256.New, s.secret, "gophkeeper/v1/server/token-key", sha256.Size)
	require.NoError(t, err)

	now := time.Now()
	claims.IssuedAt = jwt.NewNumericDate(now.Add(-time.Hour))
	claims.ExpiresAt = jwt.NewNumericDate(now.Add(-time.Minute))
	expired, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
	require.NoError(t, err)
	return expired
}

func TestSyncServerUnavailable(t *testing.T) {
	s := startServer(t)
	a := s.newClient(t)
	a.register(s, newLogin(), firstPassword)
	a.add("note")
	s.srv.Stop()

	_, err := a.run("", "sync")

	require.ErrorIs(t, err, remote.ErrUnavailable)
	assert.ErrorContains(t, err, "changes are saved locally")
	assert.Len(t, a.dirty(), 1)
}

func TestRegisterFails(t *testing.T) {
	s := startServer(t)
	a := s.newClient(t)
	login := newLogin()
	a.register(s, login, firstPassword)

	tests := []struct {
		name    string
		client  *testClient
		stdin   string
		wantErr error
		wantMsg string
	}{
		{name: "login taken", client: s.newClient(t), stdin: "p\np\n", wantErr: remote.ErrLoginTaken},
		{name: "passwords differ", client: s.newClient(t), stdin: "p\nq\n", wantErr: errPasswordMismatch},
		{name: "empty password", client: s.newClient(t), stdin: "\n\n", wantErr: errEmptyPassword},
		{name: "logged in already", client: a, stdin: "p\np\n", wantMsg: "run gophkeeper logout first"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.client.run(tt.stdin, "register", login, "--server", testServerAddress, "--ca", s.ca)
			require.Error(t, err)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			}
			assert.ErrorContains(t, err, tt.wantMsg)
		})
	}
}

func TestLoginFails(t *testing.T) {
	s := startServer(t)
	a := s.newClient(t)
	login := newLogin()
	a.register(s, login, firstPassword)

	tests := []struct {
		name    string
		client  *testClient
		args    []string
		wantErr error
		wantMsg string
	}{
		{name: "wrong password", client: s.newClient(t), args: []string{login, "--ca", s.ca}, wantErr: remote.ErrWrongCredentials},
		{name: "unknown user", client: s.newClient(t), args: []string{newLogin(), "--ca", s.ca}, wantErr: remote.ErrWrongCredentials},
		{name: "no CA", client: s.newClient(t), args: []string{login}, wantErr: errNoCA},
		{name: "CA not a certificate", client: s.newClient(t), args: []string{login, "--ca", sessionPath(t, a.app)}, wantMsg: "no certificates"},
		{name: "another user", client: a, args: []string{newLogin()}, wantMsg: "logged in as " + login},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.client.run("wrong\n", append([]string{"login"}, tt.args...)...)
			require.Error(t, err)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			}
			assert.ErrorContains(t, err, tt.wantMsg)
		})
	}
}

func TestLoginConfigPrecedence(t *testing.T) {
	s := startServer(t)
	a := s.newClient(t)
	login := newLogin()
	a.register(s, login, firstPassword)
	b := s.newClient(t)

	// The environment overrides the flags.
	t.Setenv(envPrefix+"SERVER", "localhost:9443")
	t.Setenv(envPrefix+"CA", s.ca)
	b.login(s, login, firstPassword)
	st := b.state()
	assert.Equal(t, "localhost:9443", st.ServerAddress)
	assert.Equal(t, s.ca, st.CAPath)

	// The saved values are used without the environment and the flags.
	t.Setenv(envPrefix+"SERVER", "")
	t.Setenv(envPrefix+"CA", "")
	b.enter(firstPassword+"\n", "login", login)
	assert.Equal(t, "localhost:9443", b.state().ServerAddress)

	// The flags override the saved values.
	b.enter(firstPassword+"\n", "login", login, "--server", testServerAddress)
	assert.Equal(t, testServerAddress, b.state().ServerAddress)
}

func TestUnlockWrongPasswordOnline(t *testing.T) {
	s := startServer(t)
	a := s.newClient(t)
	a.register(s, newLogin(), firstPassword)

	_, err := a.run("wrong\n", "unlock")

	assert.ErrorIs(t, err, vaultcrypto.ErrWrongPassword)
	assert.NotContains(t, err.Error(), "cannot ask the server", "the server was asked")
}

func TestLoginServerUnavailable(t *testing.T) {
	s := startServer(t)
	s.srv.Stop()

	_, err := s.newClient(t).run(firstPassword+"\n", "login", newLogin(), "--ca", s.ca)

	assert.ErrorIs(t, err, remote.ErrUnavailable)
}
