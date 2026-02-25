// Copyright 2026 TTBT Enterprises LLC
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/c2FmZQ/distfs/pkg/client"
	"github.com/c2FmZQ/distfs/pkg/metadata"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type tab int

const (
	tabOverview tab = iota
	tabUsers
	tabGroups
	tabLeases
	tabNodes
	tabTools
)

var (
	activeTabStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("205")).
			Border(lipgloss.NormalBorder(), false, false, true, false).
			BorderForeground(lipgloss.Color("205")).
			Padding(0, 1)

	inactiveTabStyle = lipgloss.NewStyle().
				Padding(0, 1)

	windowStyle = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()).
			Padding(1, 2)

	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("5")).
			MarginBottom(1)

	successStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	warningStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	neutralStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
)

type AdminClient interface {
	AdminClusterStatus(ctx context.Context) (map[string]interface{}, error)
	AdminListUsers(ctx context.Context) ([]metadata.User, error)
	AdminListGroups(ctx context.Context) ([]metadata.Group, error)
	AdminListLeases(ctx context.Context) ([]metadata.LeaseInfo, error)
	AdminListNodes(ctx context.Context) ([]metadata.Node, error)
	AdminLookup(ctx context.Context, email, reason string) (string, error)
	AdminSetUserQuota(ctx context.Context, req metadata.SetUserQuotaRequest) error
	AdminSetGroupQuota(ctx context.Context, req metadata.SetGroupQuotaRequest) error
	AdminPromote(ctx context.Context, userID string) error
	AdminJoinNode(ctx context.Context, address string) error
	AdminRemoveNode(ctx context.Context, id string) error
	DecryptGroupName(ctx context.Context, entry metadata.GroupListEntry) (string, error)
	ResolvePath(ctx context.Context, path string) (*metadata.Inode, []byte, error)
	AdminChown(ctx context.Context, inodeID string, req metadata.AdminChownRequest) error
	AdminChmod(ctx context.Context, inodeID string, mode uint32) error
}

type model struct {
	client AdminClient
	ctx    context.Context
	tab    tab

	// Data
	status map[string]interface{}
	users  []metadata.User
	groups []metadata.Group
	leases []metadata.LeaseInfo
	nodes  []metadata.Node

	// Tables
	userTable  table.Model
	groupTable table.Model
	leaseTable table.Model
	nodeTable  table.Model

	// Tools
	lookupInput  textinput.Model
	lookupResult string

	// Modals
	activeModal  string // "", "user-quota", "group-quota", "promote", "join"
	inputs       []textinput.Model
	focusedInput int

	err error

	width  int
	height int
}

type statusMsg map[string]interface{}
type usersMsg []metadata.User
type groupsMsg []metadata.Group
type leasesMsg []metadata.LeaseInfo
type nodesMsg []metadata.Node
type lookupMsg string
type errMsg error

func (m model) Init() tea.Cmd {
	return tea.Batch(
		m.fetchStatus,
		m.fetchUsers,
		m.fetchGroups,
		m.fetchLeases,
		m.fetchNodes,
		tea.Tick(2*time.Second, func(t time.Time) tea.Msg {
			return tickMsg(t)
		}),
	)
}

type tickMsg time.Time

func (m model) fetchStatus() tea.Msg {
	status, err := m.client.AdminClusterStatus(m.ctx)
	if err != nil {
		return errMsg(err)
	}
	return statusMsg(status)
}

func (m model) fetchUsers() tea.Msg {
	users, err := m.client.AdminListUsers(m.ctx)
	if err != nil {
		return errMsg(err)
	}
	return usersMsg(users)
}

func (m model) fetchGroups() tea.Msg {
	groups, err := m.client.AdminListGroups(m.ctx)
	if err != nil {
		return errMsg(err)
	}
	return groupsMsg(groups)
}

func (m model) fetchLeases() tea.Msg {
	leases, err := m.client.AdminListLeases(m.ctx)
	if err != nil {
		return errMsg(err)
	}
	return leasesMsg(leases)
}

func (m model) fetchNodes() tea.Msg {
	nodes, err := m.client.AdminListNodes(m.ctx)
	if err != nil {
		return errMsg(err)
	}
	return nodesMsg(nodes)
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	if m.err != nil {
		if _, ok := msg.(tea.KeyMsg); ok {
			m.err = nil
			return m, func() tea.Msg { return tickMsg(time.Now()) }
		}
		return m, nil
	}

	if m.activeModal != "" {
		switch msg := msg.(type) {
		case tea.KeyMsg:
			switch msg.String() {
			case "esc":
				m.activeModal = ""
				return m, nil
			case "tab", "shift+tab":
				s := msg.String()
				if s == "shift+tab" {
					m.focusedInput--
				} else {
					m.focusedInput++
				}
				if m.focusedInput < 0 {
					m.focusedInput = len(m.inputs) - 1
				} else if m.focusedInput >= len(m.inputs) {
					m.focusedInput = 0
				}
				cmds := make([]tea.Cmd, len(m.inputs))
				for i := 0; i < len(m.inputs); i++ {
					if i == m.focusedInput {
						cmds[i] = m.inputs[i].Focus()
					} else {
						m.inputs[i].Blur()
					}
				}
				return m, tea.Batch(cmds...)
			case "enter":
				// Handle Submission
				return m.handleModalSubmit()
			}
		}

		cmds := make([]tea.Cmd, len(m.inputs))
		for i := 0; i < len(m.inputs); i++ {
			m.inputs[i], cmds[i] = m.inputs[i].Update(msg)
		}
		return m, tea.Batch(cmds...)
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "1":
			m.tab = tabOverview
		case "2":
			m.tab = tabUsers
		case "3":
			m.tab = tabGroups
		case "4":
			m.tab = tabLeases
		case "5":
			m.tab = tabNodes
		case "6":
			m.tab = tabTools
			m.lookupInput.Focus()
		case "tab":
			m.tab = (m.tab + 1) % 6
			if m.tab == tabTools {
				m.lookupInput.Focus()
			}
		case "u": // User Quota
			m.activeModal = "user-quota"
			m.inputs = []textinput.Model{
				newInput("Email/UserID"),
				newInput("Max Bytes (e.g. 1048576)"),
				newInput("Max Inodes"),
			}
			m.focusedInput = 0
			m.inputs[0].Focus()
			return m, nil
		case "g": // Group Quota
			m.activeModal = "group-quota"
			m.inputs = []textinput.Model{
				newInput("Group ID"),
				newInput("Max Bytes"),
				newInput("Max Inodes"),
			}
			m.focusedInput = 0
			m.inputs[0].Focus()
			return m, nil
		case "p": // Promote
			m.activeModal = "promote"
			m.inputs = []textinput.Model{newInput("Email/UserID")}
			m.focusedInput = 0
			m.inputs[0].Focus()
			return m, nil
		case "j": // Join Node
			m.activeModal = "join"
			m.inputs = []textinput.Model{newInput("Node Address (https://node:9090)")}
			m.focusedInput = 0
			m.inputs[0].Focus()
			return m, nil
		case "r": // Remove Node
			m.activeModal = "remove"
			m.inputs = []textinput.Model{newInput("Node ID")}
			m.focusedInput = 0
			m.inputs[0].Focus()
			return m, nil
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		windowStyle.Width(m.width - 4)
		windowStyle.Height(m.height - 10)

	case statusMsg:
		m.status = msg
	case usersMsg:
		m.users = msg
		m.updateUserTable()
	case groupsMsg:
		m.groups = msg
		m.updateGroupTable()
	case leasesMsg:
		m.leases = msg
		m.updateLeaseTable()
	case nodesMsg:
		m.nodes = msg
		m.updateNodeTable()
	case lookupMsg:
		m.lookupResult = string(msg)
	case tickMsg:
		return m, tea.Batch(m.fetchStatus, m.fetchUsers, m.fetchGroups, m.fetchLeases, m.fetchNodes, tea.Tick(2*time.Second, func(t time.Time) tea.Msg {
			return tickMsg(t)
		}))
	case errMsg:
		m.err = msg
	}

	if m.tab == tabTools {
		m.lookupInput, cmd = m.lookupInput.Update(msg)
		if k, ok := msg.(tea.KeyMsg); ok && k.String() == "enter" {
			email := m.lookupInput.Value()
			if email != "" {
				return m, func() tea.Msg {
					id, err := m.client.AdminLookup(m.ctx, email, "Blind Lookup Tool")
					if err != nil {
						return lookupMsg(fmt.Sprintf("Error: %v", err))
					}
					return lookupMsg(id)
				}
			}
		}
	}

	return m, cmd
}

func (m *model) updateUserTable() {
	columns := []table.Column{
		{Title: "User ID (Hash)", Width: 40},
		{Title: "Inodes", Width: 10},
		{Title: "Storage", Width: 15},
		{Title: "Quota", Width: 15},
	}

	var rows []table.Row
	for _, u := range m.users {
		quota := "Unlim"
		if u.Quota.MaxBytes > 0 {
			quota = client.FormatBytes(u.Quota.MaxBytes)
		}
		rows = append(rows, table.Row{
			u.ID,
			fmt.Sprintf("%d", u.Usage.InodeCount),
			client.FormatBytes(u.Usage.TotalBytes),
			quota,
		})
	}

	m.userTable = table.New(
		table.WithColumns(columns),
		table.WithRows(rows),
		table.WithFocused(true),
		table.WithHeight(10),
	)
}

func (m *model) updateGroupTable() {
	columns := []table.Column{
		{Title: "Group ID", Width: 35},
		{Title: "Decrypted Name", Width: 20},
		{Title: "Inodes", Width: 10},
		{Title: "Storage", Width: 15},
		{Title: "Quota", Width: 15},
	}

	var rows []table.Row
	for _, g := range m.groups {
		quota := "Unlim"
		if g.Quota.MaxBytes > 0 {
			quota = client.FormatBytes(g.Quota.MaxBytes)
		}

		name := "[HIDDEN]"
		// Attempt to decrypt if admin has access
		// We can reuse the group list logic from the client
		if decrypted, err := m.client.DecryptGroupName(m.ctx, metadata.GroupListEntry{
			ID:         g.ID,
			ClientBlob: g.ClientBlob,
			Lockbox:    g.Lockbox,
		}); err == nil {
			name = decrypted
		}

		if g.IsSystem {
			name = "[SYSTEM] " + name
		}

		rows = append(rows, table.Row{
			g.ID,
			name,
			fmt.Sprintf("%d", g.Usage.InodeCount),
			client.FormatBytes(g.Usage.TotalBytes),
			quota,
		})
	}

	m.groupTable = table.New(
		table.WithColumns(columns),
		table.WithRows(rows),
		table.WithFocused(true),
		table.WithHeight(10),
	)
}

func (m *model) updateLeaseTable() {
	columns := []table.Column{
		{Title: "Inode ID", Width: 35},
		{Title: "Owner ID", Width: 35},
		{Title: "Expires In", Width: 15},
	}

	var rows []table.Row
	now := time.Now()
	for _, l := range m.leases {
		expiry := time.Unix(0, l.Expiry)
		remaining := expiry.Sub(now).Round(time.Second)
		if remaining < 0 {
			remaining = 0
		}

		rows = append(rows, table.Row{
			l.InodeID,
			l.SessionID,
			remaining.String(),
		})
	}

	m.leaseTable = table.New(
		table.WithColumns(columns),
		table.WithRows(rows),
		table.WithFocused(true),
		table.WithHeight(10),
	)
}

func (m *model) updateNodeTable() {
	columns := []table.Column{
		{Title: "Node ID", Width: 15},
		{Title: "Address", Width: 30},
		{Title: "Status", Width: 10},
		{Title: "Last Heartbeat", Width: 20},
	}

	var rows []table.Row
	for _, n := range m.nodes {
		rows = append(rows, table.Row{
			n.ID,
			n.Address,
			string(n.Status),
			time.Unix(n.LastHeartbeat, 0).Format("15:04:05"),
		})
	}

	m.nodeTable = table.New(
		table.WithColumns(columns),
		table.WithRows(rows),
		table.WithFocused(true),
		table.WithHeight(10),
	)
}

func (m model) View() string {
	if m.err != nil {
		return fmt.Sprintf("\n  Error: %v\n\n  Press any key to continue.", m.err)
	}

	if m.activeModal != "" {
		return m.modalView()
	}

	doc := strings.Builder{}

	// Tabs
	var tabs []string
	titles := []string{"1. Overview", "2. Users", "3. Groups", "4. Leases", "5. Nodes", "6. Tools"}
	for i, t := range titles {
		if tab(i) == m.tab {
			tabs = append(tabs, activeTabStyle.Render(t))
		} else {
			tabs = append(tabs, inactiveTabStyle.Render(t))
		}
	}
	row := lipgloss.JoinHorizontal(lipgloss.Top, tabs...)
	doc.WriteString(row)
	doc.WriteString("\n\n")

	// Content
	var content string
	switch m.tab {
	case tabOverview:
		content = m.overviewView()
	case tabUsers:
		content = m.userTable.View()
	case tabGroups:
		content = m.groupTable.View()
	case tabLeases:
		content = m.leaseTable.View()
	case tabNodes:
		content = m.nodeTable.View()
	case tabTools:
		content = m.toolsView()
	}

	doc.WriteString(windowStyle.Render(content))
	doc.WriteString("\n  (q: quit, 1-6: tabs, tab: next)\n")

	return doc.String()
}

func (m model) overviewView() string {
	if m.status == nil {
		return "Loading status..."
	}

	state := fmt.Sprintf("%v", m.status["state"])
	leader := fmt.Sprintf("%v", m.status["leader"])
	commit := "-"
	if stats, ok := m.status["stats"].(map[string]interface{}); ok {
		if c, ok := stats["commit_index"]; ok {
			commit = fmt.Sprintf("%v", c)
		}
	}

	stateDisplay := state
	switch state {
	case "Leader":
		stateDisplay = successStyle.Render(state)
	case "Candidate":
		stateDisplay = warningStyle.Render(state)
	default:
		stateDisplay = neutralStyle.Render(state)
	}

	return lipgloss.JoinVertical(lipgloss.Left,
		titleStyle.Render("Cluster Status"),
		fmt.Sprintf("State:  %s", stateDisplay),
		fmt.Sprintf("Leader: %s", leader),
		fmt.Sprintf("Commit: %s", commit),
		"",
		"Quick Actions:",
		" (u) Set User Quota",
		" (g) Set Group Quota",
		" (p) Promote Admin",
		" (j) Join Node",
		" (r) Remove Node",
	)
}

func (m model) toolsView() string {
	return lipgloss.JoinVertical(lipgloss.Left,
		titleStyle.Render("Blind Lookup"),
		"Resolve email to User ID:",
		m.lookupInput.View(),
		"",
		"Result:",
		m.lookupResult,
	)
}

func (m *model) handleModalSubmit() (tea.Model, tea.Cmd) {
	modal := m.activeModal
	m.activeModal = "" // Close modal

	refresh := func() tea.Msg {
		return tickMsg(time.Now())
	}

	switch modal {
	case "user-quota":
		email, bytesStr, inodesStr := m.inputs[0].Value(), m.inputs[1].Value(), m.inputs[2].Value()
		return m, func() tea.Msg {
			userID := email
			if !isHexID(email) {
				id, err := m.client.AdminLookup(m.ctx, email, "Quota Management")
				if err != nil {
					return errMsg(fmt.Errorf("lookup %s: %w", email, err))
				}
				userID = id
			}
			maxBytes, errBytes := strconv.ParseInt(bytesStr, 10, 64)
			maxInodes, errInodes := strconv.ParseInt(inodesStr, 10, 64)
			if errBytes != nil || errInodes != nil {
				return errMsg(fmt.Errorf("invalid numeric input: bytes=%v, inodes=%v", errBytes, errInodes))
			}
			req := metadata.SetUserQuotaRequest{UserID: userID, MaxBytes: &maxBytes, MaxInodes: &maxInodes}
			if err := m.client.AdminSetUserQuota(m.ctx, req); err != nil {
				return errMsg(err)
			}
			return refresh()
		}
	case "group-quota":
		groupID, bytesStr, inodesStr := m.inputs[0].Value(), m.inputs[1].Value(), m.inputs[2].Value()
		return m, func() tea.Msg {
			maxBytes, errBytes := strconv.ParseInt(bytesStr, 10, 64)
			maxInodes, errInodes := strconv.ParseInt(inodesStr, 10, 64)
			if errBytes != nil || errInodes != nil {
				return errMsg(fmt.Errorf("invalid numeric input: bytes=%v, inodes=%v", errBytes, errInodes))
			}
			req := metadata.SetGroupQuotaRequest{GroupID: groupID, MaxBytes: &maxBytes, MaxInodes: &maxInodes}
			if err := m.client.AdminSetGroupQuota(m.ctx, req); err != nil {
				return errMsg(err)
			}
			return refresh()
		}
	case "promote":
		email := m.inputs[0].Value()
		return m, func() tea.Msg {
			userID := email
			if !isHexID(email) {
				id, err := m.client.AdminLookup(m.ctx, email, "Quota Management")
				if err != nil {
					return errMsg(fmt.Errorf("lookup %s: %w", email, err))
				}
				userID = id
			}
			if err := m.client.AdminPromote(m.ctx, userID); err != nil {
				return errMsg(err)
			}
			return refresh()
		}
	case "join":
		addr := m.inputs[0].Value()
		return m, func() tea.Msg {
			if err := m.client.AdminJoinNode(m.ctx, addr); err != nil {
				return errMsg(err)
			}
			return refresh()
		}
	case "remove":
		id := m.inputs[0].Value()
		return m, func() tea.Msg {
			if err := m.client.AdminRemoveNode(m.ctx, id); err != nil {
				return errMsg(err)
			}
			return refresh()
		}
	}
	return m, nil
}

func (m model) modalView() string {
	var b strings.Builder
	b.WriteString("\n  " + titleStyle.Render(strings.ToUpper(m.activeModal)) + "\n\n")
	for i, input := range m.inputs {
		if i == m.focusedInput {
			b.WriteString("> ")
		} else {
			b.WriteString("  ")
		}
		b.WriteString(input.View() + "\n")
	}
	b.WriteString("\n  (enter: submit, esc: cancel, tab: next)\n")
	return windowStyle.Render(b.String())
}

func newInput(placeholder string) textinput.Model {
	ti := textinput.New()
	ti.Placeholder = placeholder
	ti.CharLimit = 156
	ti.Width = 50
	return ti
}

func cmdAdmin(ctx context.Context, args []string) {
	c := loadClient()

	ti := textinput.New()
	ti.Placeholder = "user@example.com"
	ti.CharLimit = 156
	ti.Width = 40

	m := model{
		client:      c,
		ctx:         ctx,
		tab:         tabOverview,
		lookupInput: ti,
	}

	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		log.Fatal(err)
	}
}

func cmdAdminJoin(ctx context.Context, args []string) {
	if len(args) < 1 {
		log.Fatal("node address required (e.g. http://node-2:8080)")
	}
	address := args[0]
	c := loadClient()
	if err := c.AdminJoinNode(ctx, address); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Join request for %s submitted to cluster.\n", address)
}

func cmdAdminRemove(ctx context.Context, args []string) {
	if len(args) < 1 {
		log.Fatal("node ID required")
	}
	id := args[0]
	c := loadClient()
	if err := c.AdminRemoveNode(ctx, id); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Node %s removed from cluster.\n", id)
}

func cmdAdminChown(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("admin-chown", flag.ExitOnError)
	force := fs.Bool("f", false, "Force operation without confirmation")
	if err := fs.Parse(args); err != nil {
		return
	}
	remaining := fs.Args()
	if len(remaining) < 2 {
		log.Fatal("usage: admin-chown [-f] <owner_email|owner_id>[:<new_group_id>] <path>")
	}
	ownerSpec, path := remaining[0], remaining[1]
	c := loadClient()

	var req metadata.AdminChownRequest
	parts := strings.Split(ownerSpec, ":")
	email := parts[0]

	// 1. Resolve email to UserID
	userID := email
	if !isHexID(email) {
		id, err := c.AdminLookup(ctx, email, "CLI chown")
		if err != nil {
			log.Fatalf("failed to resolve email %s: %v", email, err)
		}
		userID = id
	}
	req.OwnerID = &userID

	// 2. Resolve Group if provided
	if len(parts) > 1 {
		groupID := parts[1]
		req.GroupID = &groupID
	}

	// 3. Resolve Path to InodeID
	inode, _, err := c.ResolvePath(ctx, path)
	if err != nil {
		log.Fatalf("failed to resolve path %s: %v", path, err)
	}

	// 4. Warning
	if !*force {
		fmt.Printf("WARNING: Changing ownership of %s to %s.\n", path, email)
		fmt.Println("Existing encrypted data will NOT be readable by the new owner.")
		fmt.Print("Proceed? [y/N]: ")
		var confirm string
		fmt.Scanln(&confirm)
		if strings.ToLower(confirm) != "y" {
			fmt.Println("Aborted.")
			return
		}
	}

	if err := c.AdminChown(ctx, inode.ID, req); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Ownership updated successfully.")
}

func cmdAdminChmod(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("admin-chmod", flag.ExitOnError)
	force := fs.Bool("f", false, "Force operation without confirmation")
	if err := fs.Parse(args); err != nil {
		return
	}
	remaining := fs.Args()
	if len(remaining) < 2 {
		log.Fatal("usage: admin-chmod [-f] <mode> <path>")
	}
	modeStr, path := remaining[0], remaining[1]
	mode, err := strconv.ParseUint(modeStr, 8, 32)
	if err != nil {
		log.Fatalf("invalid mode: %v", err)
	}

	c := loadClient()
	inode, _, err := c.ResolvePath(ctx, path)
	if err != nil {
		log.Fatalf("failed to resolve path %s: %v", path, err)
	}

	if !*force {
		fmt.Printf("WARNING: Overriding permissions of %s to %s.\n", path, modeStr)
		fmt.Println("This only affects metadata visibility.")
		fmt.Print("Proceed? [y/N]: ")
		var confirm string
		fmt.Scanln(&confirm)
		if strings.ToLower(confirm) != "y" {
			fmt.Println("Aborted.")
			return
		}
	}

	if err := c.AdminChmod(ctx, inode.ID, uint32(mode)); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Permissions updated successfully.")
}

func isHexID(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func cmdAdminPromote(ctx context.Context, args []string) {
	if len(args) < 1 {
		log.Fatal("usage: admin-promote <email>")
	}
	email := args[0]
	c := loadClient()

	// Resolve email to UserID
	userID := email
	if !isHexID(email) {
		id, err := c.AdminLookup(ctx, email, "CLI promote")
		if err != nil {
			log.Fatalf("failed to resolve email %s: %v", email, err)
		}
		userID = id
	}

	if err := c.AdminPromote(ctx, userID); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("User %s promoted to Admin successfully.\n", email)
}

func cmdAdminUserQuota(ctx context.Context, args []string) {
	if len(args) < 3 {
		log.Fatal("usage: admin-user-quota <email> <max_bytes> <max_inodes>")
	}
	email, bytesStr, inodesStr := args[0], args[1], args[2]
	c := loadClient()

	userID := email
	if !isHexID(email) {
		id, err := c.AdminLookup(ctx, email, "CLI user quota")
		if err != nil {
			log.Fatalf("failed to resolve email %s: %v", email, err)
		}
		userID = id
	}

	maxBytes, _ := strconv.ParseInt(bytesStr, 10, 64)
	maxInodes, _ := strconv.ParseInt(inodesStr, 10, 64)

	req := metadata.SetUserQuotaRequest{
		UserID:    userID,
		MaxBytes:  &maxBytes,
		MaxInodes: &maxInodes,
	}

	if err := c.AdminSetUserQuota(ctx, req); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("User %s quota updated: %d bytes, %d inodes\n", email, maxBytes, maxInodes)
}

func cmdAdminGroupQuota(ctx context.Context, args []string) {
	if len(args) < 3 {
		log.Fatal("usage: admin-group-quota <group_id> <max_bytes> <max_inodes>")
	}
	groupID, bytesStr, inodesStr := args[0], args[1], args[2]
	c := loadClient()

	maxBytes, _ := strconv.ParseInt(bytesStr, 10, 64)
	maxInodes, _ := strconv.ParseInt(inodesStr, 10, 64)

	req := metadata.SetGroupQuotaRequest{
		GroupID:   groupID,
		MaxBytes:  &maxBytes,
		MaxInodes: &maxInodes,
	}

	if err := c.AdminSetGroupQuota(ctx, req); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Group %s quota updated: %d bytes, %d inodes\n", groupID, maxBytes, maxInodes)
}
