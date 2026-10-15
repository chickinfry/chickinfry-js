package invitations_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/chickinfry/chickinfry/adapters/database/postgresql"
	"github.com/chickinfry/chickinfry/auth"
)

func TestInvitationsWithPostgreSQL(t *testing.T) {
	root := os.Getenv("CHIK_JS_RUNTIME_ROOT")
	if root == "" {
		t.Fatal("CHIK_JS_RUNTIME_ROOT is required")
	}
	run := func(name string, args ...string) string {
		t.Helper()
		out, err := exec.CommandContext(t.Context(), name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s failed: %v\n%s", name, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	container := "chik-invites-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	run("docker", "run", "--rm", "-d", "--name", container, "-e", "POSTGRES_HOST_AUTH_METHOD=scram-sha-256", "-e", "POSTGRES_PASSWORD=disposable",
		"-e", "POSTGRES_USER=chik", "-e", "POSTGRES_DB=chik", "-p", "127.0.0.1::5432", "postgres:17-alpine")
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if out, err := exec.CommandContext(ctx, "docker", "rm", "-f", "-v", container).CombinedOutput(); err != nil {
			t.Errorf("container cleanup failed: %v\n%s", err, out)
		}
	})
	connection := "postgresql://chik:disposable@" + run("docker", "port", container, "5432/tcp") + "/chik?sslmode=disable"
	deadline := time.Now().Add(30 * time.Second)
	for postgresql.Probe(t.Context(), connection) != nil {
		if time.Now().After(deadline) {
			t.Fatal("disposable PostgreSQL did not become ready")
		}
		select {
		case <-time.After(100 * time.Millisecond):
		case <-t.Context().Done():
			t.Fatal(t.Context().Err())
		}
	}
	cert, key := filepath.Join(t.TempDir(), "cert.pem"), filepath.Join(t.TempDir(), "key.pem")
	run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert,
		"-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1")
	run("docker", "cp", cert, container+":/tmp/cert.pem")
	run("docker", "cp", key, container+":/tmp/key.pem")
	run("docker", "exec", "-u", "root", container, "chown", "postgres:postgres", "/tmp/cert.pem", "/tmp/key.pem")
	run("docker", "exec", "-u", "root", container, "chmod", "600", "/tmp/key.pem")
	for _, statement := range []string{
		"ALTER SYSTEM SET ssl='on'", "ALTER SYSTEM SET ssl_cert_file='/tmp/cert.pem'",
		"ALTER SYSTEM SET ssl_key_file='/tmp/key.pem'", "SELECT pg_reload_conf()",
	} {
		run("docker", "exec", "-u", "postgres", container, "psql", "-U", "chik", "-d", "chik", "-v", "ON_ERROR_STOP=1", "-c", statement)
	}
	if _, err := postgresql.Migrate(t.Context(), connection, auth.Schema()); err != nil {
		t.Fatal(err)
	}
	for _, script := range []string{"verify-sessions.js", "verify-invites.js", "verify-postgres.js", "verify-signup-hook.js"} {
		command := exec.CommandContext(t.Context(), "node", filepath.Join(root, "test", script))
		command.Env = append(os.Environ(), "CHIK_TEST_DATABASE_URL="+connection, "CHIK_TEST_DATABASE_CA="+cert, "CHIK_TEST_DATABASE_KEY="+key)
		if out, err := command.CombinedOutput(); err != nil {
			t.Fatalf("%s failed: %v\n%s", script, err, out)
		} else {
			t.Log(strings.TrimSpace(string(out)))
		}
	}
}
