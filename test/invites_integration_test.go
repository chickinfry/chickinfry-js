package invitations_test

import (
	"context"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/chickinfry/chickinfry/adapters/database/postgresql"
	"github.com/chickinfry/chickinfry/auth/migration"
	"github.com/jackc/pgx/v5"
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
	module, err := migration.Load()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := pgx.Connect(t.Context(), connection)
	if err != nil {
		t.Fatal("cannot connect to the disposable authentication database")
	}
	defer conn.Close(context.Background())
	for _, feature := range []string{"core", "email_verification"} {
		for _, step := range module.Features[feature] {
			tx, err := conn.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(t.Context(), string(step.SQL)); err != nil {
				tx.Rollback(t.Context())
				t.Fatalf("authentication module step %s/%d failed", feature, step.Version)
			}
			_, err = tx.Exec(
				t.Context(),
				`INSERT INTO public.app_auth_migrations(feature,version,name,digest,phase) VALUES($1,$2,$3,$4,$5)`,
				step.Feature,
				step.Version,
				step.Name,
				hex.EncodeToString(step.Digest[:]),
				string(step.Phase),
			)
			if err != nil {
				tx.Rollback(t.Context())
				t.Fatal("cannot record the authentication module step")
			}
			if err := tx.Commit(t.Context()); err != nil {
				t.Fatal("cannot commit the authentication module step")
			}
		}
	}
	actual, err := migration.Inspect(t.Context(), conn)
	if err != nil {
		t.Fatal(err)
	}
	if err := migration.Compare(actual, module.Manifest); err != nil {
		t.Fatal(err)
	}
	for _, script := range []string{
		"verify-sessions.js", "verify-invites.js", "verify-postgres.js", "verify-signup-hook.js",
		"verify-auth-email.js",
	} {
		t.Run(script, func(t *testing.T) {
			command := exec.CommandContext(
				t.Context(),
				"node",
				"--test",
				"--test-reporter=tap",
				filepath.Join(root, "test", script),
			)
			command.Dir = root
			command.Env = append(os.Environ(),
				"CHIK_TEST_DATABASE_URL="+connection,
				"CHIK_TEST_DATABASE_CA="+cert,
				"CHIK_TEST_DATABASE_KEY="+key,
				"CHIK_REQUIRE_URL_CORPUS=1",
			)
			out, err := command.CombinedOutput()
			summary := []string{}
			for line := range strings.SplitSeq(string(out), "\n") {
				if strings.HasPrefix(line, "# tests ") || strings.HasPrefix(line, "# pass ") ||
					strings.HasPrefix(line, "# fail ") || strings.HasPrefix(line, "# skipped ") {
					summary = append(summary, line)
				}
			}
			if err != nil {
				pattern := regexp.MustCompile(
					regexp.QuoteMeta(script) + `:[0-9]+:[0-9]+|ERR_[A-Z_]+|code: '[A-Z0-9]{5}'`,
				)
				summary = append(summary, pattern.FindAllString(string(out), -1)...)
			}
			t.Log(strings.Join(summary, ", "))
			if err != nil {
				t.Fatalf("%s failed: %v (raw output omitted to protect authentication values)", script, err)
			}
			if !slices.Contains(summary, "# skipped 0") {
				t.Fatalf("%s did not report zero skipped tests", script)
			}
		})
	}
}
