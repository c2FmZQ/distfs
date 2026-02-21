package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/c2FmZQ/distfs/pkg/client"
	"github.com/c2FmZQ/distfs/pkg/metadata"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

type mockAdminClient struct {
	status map[string]interface{}
	users  []metadata.User
	groups []metadata.Group
	leases []metadata.LeaseInfo
	nodes  []metadata.Node
	err    error
}

func (m *mockAdminClient) AdminClusterStatus(ctx context.Context) (map[string]interface{}, error) {
	return m.status, m.err
}
func (m *mockAdminClient) AdminListUsers(ctx context.Context) ([]metadata.User, error) {
	return m.users, m.err
}
func (m *mockAdminClient) AdminListGroups(ctx context.Context) ([]metadata.Group, error) {
	return m.groups, m.err
}
func (m *mockAdminClient) AdminListLeases(ctx context.Context) ([]metadata.LeaseInfo, error) {
	return m.leases, m.err
}
func (m *mockAdminClient) AdminListNodes(ctx context.Context) ([]metadata.Node, error) {
	return m.nodes, m.err
}
func (m *mockAdminClient) AdminLookup(ctx context.Context, email, reason string) (string, error) {
	return "user-id-123", m.err
}
func (m *mockAdminClient) AdminSetUserQuota(ctx context.Context, req metadata.SetUserQuotaRequest) error {
	return m.err
}
func (m *mockAdminClient) AdminSetGroupQuota(ctx context.Context, req metadata.SetGroupQuotaRequest) error {
	return m.err
}
func (m *mockAdminClient) AdminPromote(ctx context.Context, userID string) error {
	return m.err
}
func (m *mockAdminClient) AdminJoinNode(ctx context.Context, address string) error {
	return m.err
}

func (m *mockAdminClient) AdminRemoveNode(ctx context.Context, id string) error {
	return m.err
}
func (m *mockAdminClient) DecryptGroupName(entry metadata.GroupListEntry) (string, error) {
	return "decrypted-group", m.err
}
func (m *mockAdminClient) ResolvePath(path string) (*metadata.Inode, []byte, error) {
	return &metadata.Inode{ID: "inode-123"}, []byte("key"), m.err
}
func (m *mockAdminClient) AdminChown(ctx context.Context, inodeID string, req metadata.AdminChownRequest) error {
	return m.err
}
func (m *mockAdminClient) AdminChmod(ctx context.Context, inodeID string, mode uint32) error {
	return m.err
}

func TestAdminConsole_TabSwitching(t *testing.T) {
	m := model{
		client: &mockAdminClient{},
	}

	// Test Initial Tab
	if m.tab != tabOverview {
		t.Errorf("expected initial tab to be Overview, got %v", m.tab)
	}

	// Press '2' for Users
	newModel, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("2")})
	m = newModel.(model)
	if m.tab != tabUsers {
		t.Errorf("expected tab to be Users, got %v", m.tab)
	}

	// Press '3' for Groups
	newModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("3")})
	m = newModel.(model)
	if m.tab != tabGroups {
		t.Errorf("expected tab to be Groups, got %v", m.tab)
	}

	// Press 'tab' to cycle
	newModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyTab})
	m = newModel.(model)
	if m.tab != tabLeases {
		t.Errorf("expected tab to be Leases, got %v", m.tab)
	}
}

func TestAdminConsole_Modals(t *testing.T) {
	m := model{
		client: &mockAdminClient{},
	}

	// Press 'u' to open User Quota modal
	newModel, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("u")})
	m = newModel.(model)
	if m.activeModal != "user-quota" {
		t.Errorf("expected modal to be user-quota, got %s", m.activeModal)
	}
	if len(m.inputs) != 3 {
		t.Errorf("expected 3 inputs for user quota, got %d", len(m.inputs))
	}

	// Press 'esc' to cancel
	newModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = newModel.(model)
	if m.activeModal != "" {
		t.Errorf("expected modal to be closed, got %s", m.activeModal)
	}

	// Press 'p' to open Promote modal
	newModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("p")})
	m = newModel.(model)
	if m.activeModal != "promote" {
		t.Errorf("expected modal to be promote, got %s", m.activeModal)
	}

	// Enter text into input
	newModel, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("a")})
	newModel, _ = newModel.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("b")})
	m = newModel.(model)
	if m.inputs[0].Value() != "ab" {
		t.Errorf("expected input value 'ab', got %s", m.inputs[0].Value())
	}
}

func TestAdminConsole_DataRendering(t *testing.T) {
	client := &mockAdminClient{
		status: map[string]interface{}{
			"state":  "Leader",
			"leader": "127.0.0.1:8080",
		},
		users: []metadata.User{
			{ID: "user1", Usage: metadata.UserUsage{InodeCount: 5}},
		},
	}
	m := model{
		client: client,
	}

	// Load data manually via Update (mocking Init's async commands)
	m.status = client.status
	m.users = client.users
	m.updateUserTable()

	// Check Overview
	m.tab = tabOverview
	view := m.View()
	if !strings.Contains(view, "Leader") {
		t.Errorf("View missing Raft state 'Leader'")
	}

	// Check Users
	m.tab = tabUsers
	view = m.View()
	if !strings.Contains(view, "user1") {
		t.Errorf("View missing User ID 'user1'")
	}
}

func TestAdminConsole_ModalSubmission(t *testing.T) {
	client := &mockAdminClient{}
	m := model{
		client: client,
	}

	// Test Promote Modal Submission
	m.activeModal = "promote"
	m.inputs = []textinput.Model{newInput("Email/UserID")}
	m.inputs[0].SetValue("user-to-promote")

	newModel, cmd := m.handleModalSubmit()
	m = *newModel.(*model)

	if m.activeModal != "" {
		t.Errorf("expected modal to be closed after submission")
	}

	if cmd == nil {
		t.Fatalf("expected a command to be returned from modal submission")
	}

	// Execute the command
	msg := cmd()
	if _, ok := msg.(tickMsg); !ok {
		if err, ok := msg.(errMsg); ok {
			t.Errorf("unexpected error msg: %v", err)
		}
	}
}

func TestAdminConsole_AllTabs(t *testing.T) {
	client := &mockAdminClient{
		status: map[string]interface{}{"state": "Leader"},
		users:  []metadata.User{{ID: "u1"}},
		groups: []metadata.Group{{ID: "g1"}},
		leases: []metadata.LeaseInfo{{InodeID: "i1"}},
		nodes:  []metadata.Node{{ID: "n1"}},
	}
	m := model{
		client: client,
	}
	m.updateUserTable()
	m.updateGroupTable()
	m.updateLeaseTable()
	m.updateNodeTable()

	tabs := []tab{tabOverview, tabUsers, tabGroups, tabLeases, tabNodes, tabTools}
	for _, tab := range tabs {
		m.tab = tab
		view := m.View()
		if view == "" {
			t.Errorf("tab %v returned empty view", tab)
		}
	}
}

func TestAdminConsole_WindowSize(t *testing.T) {
	m := model{}
	newModel, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 50})
	m = newModel.(model)
	if m.width != 100 || m.height != 50 {
		t.Errorf("expected size 100x50, got %dx%d", m.width, m.height)
	}
}

func TestAdminConsole_Tick(t *testing.T) {
	client := &mockAdminClient{}
	m := model{client: client}

	// TickMsg should trigger fetches
	_, cmd := m.Update(tickMsg(time.Now()))
	if cmd == nil {
		t.Errorf("expected command on tick")
	}
}

func TestAdminConsole_Lookup(t *testing.T) {
	client := &mockAdminClient{}
	m := model{
		client:      client,
		tab:         tabTools,
		lookupInput: newInput("test"),
	}

	m.lookupInput.SetValue("test@example.com")
	newModel, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = newModel.(model)

	if cmd == nil {
		t.Fatalf("expected command for lookup")
	}

	msg := cmd()
	if res, ok := msg.(lookupMsg); ok {
		if string(res) != "user-id-123" {
			t.Errorf("expected lookup result 'user-id-123', got %s", res)
		}
	} else {
		t.Errorf("expected lookupMsg, got %T", msg)
	}
}

func TestAdminConsole_ErrorHandling(t *testing.T) {
	m := model{
		client: &mockAdminClient{},
		err:    errors.New("some error"),
	}

	view := m.View()
	if !strings.Contains(view, "Error: some error") {
		t.Errorf("View missing error message")
	}

	// Pressing a key should clear error
	newModel, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = newModel.(model)
	if m.err != nil {
		t.Errorf("expected error to be cleared")
	}
}

func TestAdminConsole_Utilities(t *testing.T) {
	// Test formatBytes
	tests := []struct {
		bytes int64
		want  string
	}{
		{500, "500 B"},
		{1024, "1.0 KB"},
		{1024 * 1024, "1.0 MB"},
		{1024 * 1024 * 1024, "1.0 GB"},
	}
	for _, tt := range tests {
		if got := client.FormatBytes(tt.bytes); got != tt.want {
			t.Errorf("FormatBytes(%d) = %v, want %v", tt.bytes, got, tt.want)
		}
	}

	// Test isHexID
	if !isHexID(strings.Repeat("a", 64)) {
		t.Errorf("expected 64 'a's to be hex ID")
	}
	if isHexID("not-hex") {
		t.Errorf("expected 'not-hex' to not be hex ID")
	}
	if isHexID(strings.Repeat("a", 63)) {
		t.Errorf("expected 63 'a's to not be hex ID")
	}
}
