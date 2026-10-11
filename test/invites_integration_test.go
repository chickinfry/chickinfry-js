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
	run("docker", "run", "--rm", "-d", "--name", container, "-e", "POSTGRES_HOST_AUTH_METHOD=trust",
		"-e", "POSTGRES_USER=chik", "-e", "POSTGRES_DB=chik", "-p", "127.0.0.1::5432", "postgres:17-alpine")
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if out, err := exec.CommandContext(ctx, "docker", "rm", "-f", container).CombinedOutput(); err != nil {
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
	if _, err := postgresql.Migrate(t.Context(), connection, auth.Schema()); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(t.Context(), "node", filepath.Join(root, "test/verify-invites.js"))
	command.Env = append(os.Environ(), "CHIK_TEST_DATABASE_URL="+connection)
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("invitation verification failed: %v\n%s", err, out)
	} else {
		t.Log(strings.TrimSpace(string(out)))
	}
}
