package store

import "testing"

func TestSecretsCRUD(t *testing.T) {
	st, err := New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	defer st.Close()

	sec := Secret{ID: "sec_1", Name: "db-pass", Selector: ""}
	v1 := SecretVersion{ID: "secv_1", SecretID: "sec_1", Version: 1, Ciphertext: []byte("ct-1")}
	if err := st.CreateSecret(sec, v1); err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	// Binding rows reference a real agent (FK).
	if err := st.UpsertAgent(Agent{ID: "ag_1", UUID: "uuid-1", ED25519Pub: "e1", X25519Pub: "x1"}); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}

	got, err := st.GetSecret("db-pass")
	if err != nil {
		t.Fatalf("GetSecret by name: %v", err)
	}
	if got.ID != "sec_1" {
		t.Fatalf("GetSecret: id = %q, want sec_1", got.ID)
	}

	// Duplicate name rejected (UNIQUE).
	if err := st.CreateSecret(Secret{ID: "sec_2", Name: "db-pass"}, v1); err == nil {
		t.Fatal("duplicate name: want error")
	}

	// Rotate → v2, v1 revoked.
	v, err := st.RotateSecret("sec_1", []byte("ct-v2"))
	if err != nil {
		t.Fatalf("RotateSecret: %v", err)
	}
	if v != 2 {
		t.Fatalf("rotate version = %d, want 2", v)
	}
	latest, err := st.GetLatestSecretVersion("sec_1")
	if err != nil {
		t.Fatalf("GetLatest: %v", err)
	}
	if latest.Version != 2 || string(latest.Ciphertext) != "ct-v2" {
		t.Fatalf("latest = v%d %q, want v2 ct-v2", latest.Version, latest.Ciphertext)
	}
	old, err := st.GetSecretVersion("sec_1", 1)
	if err != nil {
		t.Fatalf("GetSecretVersion(1): %v", err)
	}
	if !old.Revoked {
		t.Fatal("v1 should be revoked after rotation")
	}

	// Binding audit.
	if err := st.RecordSecretBinding(SecretBinding{SecretID: "sec_1", Version: 2, AgentID: "ag_1", Ref: "run_1"}); err != nil {
		t.Fatalf("RecordSecretBinding: %v", err)
	}
	binds, err := st.ListSecretBindings("sec_1", 10)
	if err != nil {
		t.Fatalf("ListSecretBindings: %v", err)
	}
	if len(binds) != 1 || binds[0].Version != 2 || binds[0].AgentID != "ag_1" || binds[0].Ref != "run_1" {
		t.Fatalf("bindings = %+v", binds)
	}

	// List + delete cascade.
	list, err := st.ListSecrets()
	if err != nil {
		t.Fatalf("ListSecrets: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("ListSecrets = %d, want 1", len(list))
	}
	if err := st.DeleteSecret("db-pass"); err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}
	if _, err := st.GetSecret("db-pass"); err != ErrNotFound {
		t.Fatalf("GetSecret after delete = %v, want ErrNotFound", err)
	}
	if _, err := st.GetLatestSecretVersion("sec_1"); err != ErrNotFound {
		t.Fatalf("versions should cascade-delete: %v", err)
	}
}

func TestSecretsRevoke(t *testing.T) {
	st, err := New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	defer st.Close()

	sec := Secret{ID: "sec_9", Name: "tok", Selector: ""}
	v1 := SecretVersion{ID: "secv_9", SecretID: "sec_9", Version: 1, Ciphertext: []byte("ct")}
	if err := st.CreateSecret(sec, v1); err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	if err := st.RevokeSecretVersion("sec_9", 1); err != nil {
		t.Fatalf("RevokeSecretVersion: %v", err)
	}
	if _, err := st.GetLatestSecretVersion("sec_9"); err != ErrNotFound {
		t.Fatalf("GetLatest after revoke = %v, want ErrNotFound", err)
	}
	if err := st.RevokeSecretVersion("sec_9", 1); err == nil {
		t.Fatal("second revoke: want error")
	}
}
