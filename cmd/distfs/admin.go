// Copyright 2026 TTBT Enterprises LLC
package main

import (
	"context"
	"flag"
	"fmt"
	"iter"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/c2FmZQ/distfs/pkg/client"
	"github.com/c2FmZQ/distfs/pkg/crypto"
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
	AdminListUsers(ctx context.Context) iter.Seq2[*metadata.User, error]
	AdminListGroups(ctx context.Context) iter.Seq2[*metadata.Group, error]
	AdminListLeases(ctx context.Context) iter.Seq2[*metadata.LeaseInfo, error]
	AdminListNodes(ctx context.Context) iter.Seq[*metadata.Node]
	ResolveUsername(ctx context.Context, identifier string) (string, *client.DirectoryEntry, error)
	AdminSetUserQuota(ctx context.Context, req metadata.SetUserQuotaRequest) error
	AdminSetGroupQuota(ctx context.Context, req metadata.SetGroupQuotaRequest) error
	AdminPromote(ctx context.Context, userID string) error
	AdminJoinNode(ctx context.Context, address string) error
	AdminRemoveNode(ctx context.Context, id string) error
	DecryptGroupName(ctx context.Context, entry metadata.GroupListEntry) (string, error)
	ResolvePath(ctx context.Context, path string) (*metadata.Inode, []byte, error)
	MkdirExtended(ctx context.Context, path string, perm os.FileMode, opts client.MkdirOptions) error
}

type model struct {
	client AdminClient
	ctx    context.Context
	tab    tab

	// Data
	status map[string]interface{}
	users  []*metadata.User
	groups []*metadata.Group
	leases []*metadata.LeaseInfo
	nodes  []*metadata.Node

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
type usersMsg []*metadata.User
type groupsMsg []*metadata.Group
type leasesMsg []*metadata.LeaseInfo
type nodesMsg []*metadata.Node
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
	var users []*metadata.User
	for u, err := range m.client.AdminListUsers(m.ctx) {
		if err != nil {
			return errMsg(err)
		}
		users = append(users, u)
	}
	return usersMsg(users)
}

func (m model) fetchGroups() tea.Msg {
	var groups []*metadata.Group
	for g, err := range m.client.AdminListGroups(m.ctx) {
		if err != nil {
			return errMsg(err)
		}
		groups = append(groups, g)
	}
	return groupsMsg(groups)
}

func (m model) fetchLeases() tea.Msg {
	var leases []*metadata.LeaseInfo
	for l, err := range m.client.AdminListLeases(m.ctx) {
		if err != nil {
			return errMsg(err)
		}
		leases = append(leases, l)
	}
	return leasesMsg(leases)
}

func (m model) fetchNodes() tea.Msg {
	var nodes []*metadata.Node
	for n := range m.client.AdminListNodes(m.ctx) {
		nodes = append(nodes, n)
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
					id, _, err := m.client.ResolveUsername(m.ctx, email)
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
				id, _, err := m.client.ResolveUsername(m.ctx, email)
				if err != nil {
					return errMsg(fmt.Errorf("lookup %s: %w", email, err))
				}
				userID = id
			}
			maxBytes, errBytes := strconv.ParseUint(bytesStr, 10, 64)
			maxInodes, errInodes := strconv.ParseUint(inodesStr, 10, 64)
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
			maxBytes, errBytes := strconv.ParseUint(bytesStr, 10, 64)
			maxInodes, errInodes := strconv.ParseUint(inodesStr, 10, 64)
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
				id, _, err := m.client.ResolveUsername(m.ctx, email)
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

func cmdAdminPromote(ctx context.Context, args []string) {
	if len(args) < 1 {
		log.Fatal("usage: admin-promote <email>")
	}
	email := args[0]
	c := loadClient()

	// Resolve email/username to UserID
	userID := email
	if !isHexID(email) {
		id, _, err := c.ResolveUsername(ctx, email)
		if err != nil {
			log.Fatalf("failed to resolve user %s: %v", email, err)
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
		id, _, err := c.ResolveUsername(ctx, email)
		if err != nil {
			log.Fatalf("failed to resolve user %s: %v", email, err)
		}
		userID = id
	}

	maxBytes, _ := strconv.ParseUint(bytesStr, 10, 64)
	maxInodes, _ := strconv.ParseUint(inodesStr, 10, 64)

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

	maxBytes, _ := strconv.ParseUint(bytesStr, 10, 64)
	maxInodes, _ := strconv.ParseUint(inodesStr, 10, 64)

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

func cmdAdminCreateRoot(ctx context.Context, args []string) {
	id := metadata.RootID
	if len(args) > 0 {
		id = args[0]
		if !metadata.IsInodeID(id) {
			log.Fatalf("invalid inode ID: %s", id)
		}
	}

	c := loadClient()
	c = c.WithRootID(id)

	if err := c.EnsureRoot(ctx); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Root inode %s initialized successfully.\n", id)

	// Phase 49: System Backbone Bootstrapping
	// Only do this for the canonical root to avoid cluttering secondary roots.
	if id == metadata.RootID {
		fmt.Println("Bootstrapping system backbone...")

		// 1. Create Admin Group
		adminGroup, err := c.CreateGroup(ctx, "admin", false)
		if err != nil && !strings.Contains(err.Error(), "already exists") {
			log.Printf("Warning: failed to create admin group: %v", err)
		}

		// 2. Create System Groups (owned by admin group)
		var registryGroupID, usersGroupID string
		if adminGroup != nil {
			// Registry Group
			regGroup, err := c.CreateGroup(ctx, "registry", true) // Quota enabled
			if err == nil {
				registryGroupID = regGroup.ID
				// Chown to admin group
				_, err = c.UpdateGroup(ctx, regGroup.ID, func(g *metadata.Group) error {
					g.OwnerID = ":" + adminGroup.ID
					return nil
				})
			}

			// Users Group
			usrGroup, err := c.CreateGroup(ctx, "users", true) // Quota enabled
			if err == nil {
				usersGroupID = usrGroup.ID
				// Chown to admin group
				_, err = c.UpdateGroup(ctx, usrGroup.ID, func(g *metadata.Group) error {
					g.OwnerID = ":" + adminGroup.ID
					return nil
				})
			}
		}

		// 3. Create Backbone Directories
		// /registry
		optsReg := client.MkdirOptions{}
		if err := c.MkdirExtended(ctx, "/registry", 0775, optsReg); err != nil && !strings.Contains(err.Error(), "already exists") {
			log.Printf("Warning: failed to create /registry: %v", err)
		} else if registryGroupID != "" {
			c.SetAttr(ctx, "/registry", metadata.SetAttrRequest{GroupID: &registryGroupID})
		}

		// /users
		optsUsr := client.MkdirOptions{}
		if err := c.MkdirExtended(ctx, "/users", 0755, optsUsr); err != nil && !strings.Contains(err.Error(), "already exists") {
			log.Printf("Warning: failed to create /users: %v", err)
		} else if usersGroupID != "" {
			c.SetAttr(ctx, "/users", metadata.SetAttrRequest{GroupID: &usersGroupID})
		}

		// 4. Initial Registry Entry (Admin self-attestation)
		// To do this, we need GenerateContactString logic adapted for DirectoryEntry.
		// For now, we print a message that it should be done via registry-add.
		fmt.Println("Backbone provisioned. Use 'distfs registry-add' to populate the registry.")
	}
}

func cmdAdminAudit(ctx context.Context, args []string) {
	c := loadClient()

	fmt.Println("=== DISTFS SYSTEM AUDIT & STRUCTURAL INTEGRITY ===")
	fmt.Println("Running linearizable leader scan...")
	fmt.Println("")

	roots, orphans, reports, users, groups, nodes, gc, allInodes, err := c.AdminAuditForest(ctx)
	if err != nil {
		log.Fatalf("Audit failed: %v", err)
	}

	fmt.Println("TREE FOREST:")
	visited := make(map[string]bool)

	var printTree func(id string, nameHMAC string, indent string, isLast bool)
	printTree = func(id string, nameHMAC string, indent string, isLast bool) {
		inode, ok := allInodes[id]
		if !ok {
			fmt.Printf("%s%s [MISSING INODE]\n", indent, id)
			return
		}

		marker := "├── "
		if isLast {
			marker = "└── "
		}

		display := nameHMAC
		if display == "" {
			display = inode.ID[:8]
		}

		info := fmt.Sprintf("[%s] [Owner: %s] [Mode: %04o]", inode.ID[:8], inode.OwnerID[:8], inode.Mode)
		if inode.Type == metadata.DirType {
			fmt.Printf("%s%s%s/ %s\n", indent, marker, display, info)
		} else {
			fmt.Printf("%s%s%s %s [Size: %d]\n", indent, marker, display, info, inode.Size)
		}

		if visited[id] {
			return
		}
		visited[id] = true

		if inode.Type == metadata.DirType && len(inode.Children) > 0 {
			newIndent := indent + "│   "
			if isLast {
				newIndent = indent + "    "
			}

			// Sort children by HMAC for deterministic output
			hmacs := make([]string, 0, len(inode.Children))
			for h := range inode.Children {
				hmacs = append(hmacs, h)
			}
			sort.Strings(hmacs)

			for i, h := range hmacs {
				childID := inode.Children[h]
				printTree(childID, h, newIndent, i == len(hmacs)-1)
			}
		}
	}

	for _, root := range roots {
		title := "Implicit Root"
		if root.ID == metadata.RootID {
			title = "Canonical Root"
		}
		fmt.Printf("%s: %s\n", title, root.ID)
		printTree(root.ID, "", "", true)
		fmt.Println("")
	}

	if len(orphans) > 0 {
		fmt.Println("ORPHANED / DISCONNECTED INODES:")
		for _, o := range orphans {
			fmt.Printf("! %s [Owner: %s] [Size: %d] [Links: %d]\n", o.ID, o.OwnerID[:8], o.Size, len(o.Links))
		}
		fmt.Println("")
	}

	fmt.Println("ACTOR REGISTRY:")
	for _, u := range users {
		adminStr := ""
		if u.IsAdmin {
			adminStr = " [ADMIN]"
		}
		fmt.Printf("User: %s [UID: %d] [Usage: %d files, %d bytes] [Quota: %d/%d]%s\n",
			u.ID[:16], u.UID, u.Usage.InodeCount, u.Usage.TotalBytes, u.Quota.MaxInodes, u.Quota.MaxBytes, adminStr)
	}
	for _, g := range groups {
		fmt.Printf("Group: %s [GID: %d] [Usage: %d files, %d bytes] [Quota: %d/%d] [Members: %d]\n",
			g.ID[:16], g.GID, g.Usage.InodeCount, g.Usage.TotalBytes, g.Quota.MaxInodes, g.Quota.MaxBytes, g.MemberCount)
	}
	fmt.Println("")

	fmt.Println("INFRASTRUCTURE:")
	for _, n := range nodes {
		fmt.Printf("Node: %s [%s] [Status: %s] [Storage: %d/%d MB]\n",
			n.ID, n.Address, n.Status, n.Used/(1024*1024), n.Capacity/(1024*1024))
	}
	fmt.Println("")

	fmt.Println("LIFECYCLE:")
	fmt.Printf("GC Queue Depth: %d chunks pending deletion\n", len(gc))
	fmt.Println("")

	if len(reports) > 0 {
		fmt.Println("INTEGRITY VIOLATIONS DETECTED:")
		for _, r := range reports {
			fmt.Printf("FAIL: [%s] Target: %s - %s\n", r.Type, r.TargetID, r.Message)
		}
	} else {
		fmt.Println("INTEGRITY CHECK: PASS")
	}
	fmt.Println("")
}

func findRedactedInode(roots, orphans []*metadata.RedactedInode, id string) (*metadata.RedactedInode, bool) {
	for _, r := range roots {
		if r.ID == id {
			return r, true
		}
	}
	for _, o := range orphans {
		if o.ID == id {
			return o, true
		}
	}
	return nil, false
}

func cmdRegistryAdd(ctx context.Context, args []string) {
	fs := flag.NewFlagSet("registry-add", flag.ExitOnError)
	unlock := fs.Bool("unlock", false, "Unlock the user account after verification")
	quota := fs.String("quota", "", "Set user quota (format: bytes,inodes e.g. 1000000,5000)")
	home := fs.Bool("home", false, "Provision a home directory in /users/<username>")
	fs.Parse(args)

	if fs.NArg() < 2 {
		log.Fatal("usage: registry-add [--unlock] [--quota <bytes,inodes>] [--home] <username> <email>")
	}
	username := fs.Arg(0)
	email := fs.Arg(1)

	c := loadClient()

	// 1. Server Discovery
	userID := email
	if !isHexID(email) {
		id, _, err := c.ResolveUsername(ctx, email)
		if err != nil {
			log.Fatalf("Failed to resolve email to UserID: %v", err)
		}
		userID = id
	}

	user, err := c.GetUser(ctx, userID)
	if err != nil {
		log.Fatalf("Failed to fetch user from server: %v", err)
	}

	// 2. OOB Handshake (Simulation for CLI)
	// Compute a deterministic "verification code" based on the user's public keys.
	h := crypto.NewHash()
	h.Write(user.EncKey)
	h.Write(user.SignKey)
	codeBytes := h.Sum(nil)
	codeStr := fmt.Sprintf("%02X-%02X-%02X", codeBytes[0], codeBytes[1], codeBytes[2])

	fmt.Printf("\n--- OUT-OF-BAND VERIFICATION REQUIRED ---\n")
	fmt.Printf("User: %s (%s)\n", username, email)
	fmt.Printf("Please contact this user out-of-band (e.g., via phone or Signal).\n")
	fmt.Printf("Ask them to verify their security code matches: %s\n", codeStr)
	fmt.Printf("-----------------------------------------\n")
	fmt.Printf("Does the code match? [y/N]: ")

	var response string
	fmt.Scanln(&response)
	if strings.ToLower(strings.TrimSpace(response)) != "y" {
		log.Fatal("Verification aborted.")
	}

	// 3. Attestation & Registry Update
	// For simplicity in this iteration, we create an empty file with the Username
	// to represent the attestation. In a real scenario, this would be a signed JSON blob.
	regPath := *registryDir + "/" + username + ".user"

	// Ensure registry directory exists
	err = c.Mkdir(ctx, *registryDir, 0775)
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		log.Fatalf("Failed to access registry directory: %v", err)
	}

	entry := client.DirectoryEntry{
		Username: username,
		Email:    email,
		UserID:   user.ID,
		EncKey:   user.EncKey,
		SignKey:  user.SignKey,
		// TODO: Sign this entry with the admin's (verifier's) private key
	}

	err = c.SaveDataFile(ctx, regPath, entry)
	if err != nil {
		log.Fatalf("Failed to write registry entry: %v", err)
	}

	mode := uint32(0644)
	if err := c.SetAttr(ctx, regPath, metadata.SetAttrRequest{Mode: &mode}); err != nil {
		log.Fatalf("Failed to make registry entry world-readable: %v", err)
	}

	fmt.Printf("Successfully added %s to the registry.\n", username)

	// 4. Handle Flags
	if *unlock {
		err := c.AdminSetUserLock(ctx, user.ID, false)
		if err != nil {
			log.Fatalf("Failed to unlock user: %v", err)
		}
		fmt.Println("User unlocked.")
	}

	if *quota != "" {
		parts := strings.Split(*quota, ",")
		if len(parts) != 2 {
			log.Fatalf("Invalid quota format. Expected bytes,inodes")
		}
		bytesLim, _ := strconv.ParseUint(parts[0], 10, 64)
		inodesLim, _ := strconv.ParseUint(parts[1], 10, 64)
		err := c.AdminSetUserQuota(ctx, metadata.SetUserQuotaRequest{
			UserID:    user.ID,
			MaxBytes:  &bytesLim,
			MaxInodes: &inodesLim,
		})
		if err != nil {
			log.Fatalf("Failed to set quota: %v", err)
		}
		fmt.Printf("User quota set: %d bytes, %d inodes.\n", bytesLim, inodesLim)
	}

	if *home {
		homePath := "/users/" + username
		// Ensure /users exists
		err = c.Mkdir(ctx, "/users", 0755)
		if err != nil && !strings.Contains(err.Error(), "already exists") {
			log.Fatalf("Failed to access /users directory: %v", err)
		}

		opts := client.MkdirOptions{OwnerID: user.ID}
		err = c.MkdirExtended(ctx, homePath, 0700, opts)
		if err != nil {
			log.Fatalf("Failed to provision home directory: %v", err)
		}
		fmt.Printf("Provisioned home directory: %s\n", homePath)
	}
}

func cmdAdminLockUser(ctx context.Context, args []string, lock bool) {
	if len(args) < 1 {
		if lock {
			log.Fatal("usage: admin-lock-user <email|username>")
		} else {
			log.Fatal("usage: admin-unlock-user <email|username>")
		}
	}
	email := args[0]
	c := loadClient()

	userID := email
	if !isHexID(email) {
		id, _, err := c.ResolveUsername(ctx, email)
		if err != nil {
			log.Fatalf("failed to resolve user %s: %v", email, err)
		}
		userID = id
	}

	if err := c.AdminSetUserLock(ctx, userID, lock); err != nil {
		log.Fatal(err)
	}

	if lock {
		fmt.Printf("User %s has been locked.\n", userID)
	} else {
		fmt.Printf("User %s has been unlocked.\n", userID)
	}
}
