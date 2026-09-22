package store

import "testing"

// TestResolver verifies the store-backed selector resolution.
func TestResolver(t *testing.T) {
	db, _ := setupTestDB(t)
	defer db.Close()

	// Seed 3 agents: 2 web/prod, 1 db/lab.
	agents := []Agent{
		{ID: "ag_web1", UUID: "u1", ED25519Pub: "kp1", X25519Pub: "x1"},
		{ID: "ag_web2", UUID: "u2", ED25519Pub: "kp2", X25519Pub: "x2"},
		{ID: "ag_db1", UUID: "u3", ED25519Pub: "kp3", X25519Pub: "x3"},
	}
	for _, a := range agents {
		if err := db.UpsertAgent(a); err != nil {
			t.Fatalf("UpsertAgent %s: %v", a.ID, err)
		}
	}
	db.SetRole("ag_web1", "web")
	db.SetRole("ag_web2", "web")
	db.SetRole("ag_db1", "db")
	db.SetTag("ag_web1", "env", "prod")
	db.SetTag("ag_web2", "env", "prod")
	db.SetTag("ag_db1", "env", "lab")

	r := NewResolver(db)

	// all → 3
	hosts, err := r.ResolveSelector("all")
	if err != nil {
		t.Fatalf("all: %v", err)
	}
	if len(hosts) != 3 {
		t.Fatalf("all = %d hosts, want 3", len(hosts))
	}

	// role:web AND tag:env=prod → web1, web2
	hosts, err = r.ResolveSelector("role:web,tag:env=prod")
	if err != nil {
		t.Fatalf("role:web,tag:env=prod: %v", err)
	}
	if len(hosts) != 2 {
		t.Fatalf("got %d hosts, want 2", len(hosts))
	}

	// host:ag_db1 → 1
	hosts, err = r.ResolveSelector("host:ag_db1")
	if err != nil {
		t.Fatalf("host:ag_db1: %v", err)
	}
	if len(hosts) != 1 || hosts[0].ID != "ag_db1" {
		t.Fatalf("host:ag_db1 = %v", hosts)
	}

	// group via saved group
	db.UpsertGroup(Group{Name: "prod", Selector: "tag:env=prod"})
	hosts, err = r.ResolveSelector("group:prod")
	if err != nil {
		t.Fatalf("group:prod: %v", err)
	}
	if len(hosts) != 2 {
		t.Fatalf("group:prod = %d hosts, want 2", len(hosts))
	}

	// impossible → error
	if _, err := r.ResolveSelector("role:web,tag:env=lab"); err == nil {
		t.Fatal("expected error for empty resolution")
	}
}
