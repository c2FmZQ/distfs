// Copyright 2026 TTBT Enterprises LLC
package main

import (
	"context"
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
)

type model struct {
	client *client.Client
	tab    tab

	// Data
	status map[string]interface{}
	users  []metadata.User
	nodes  []metadata.Node

	// Tables
	userTable table.Model
	nodeTable table.Model

	// Tools
	lookupInput  textinput.Model
	lookupResult string

	err error

	width  int
	height int
}

type statusMsg map[string]interface{}
type usersMsg []metadata.User
type nodesMsg []metadata.Node
type lookupMsg string
type errMsg error

func (m model) Init() tea.Cmd {
	return tea.Batch(
		m.fetchStatus,
		m.fetchUsers,
		m.fetchNodes,
		tea.Tick(2*time.Second, func(t time.Time) tea.Msg {
			return tickMsg(t)
		}),
	)
}

type tickMsg time.Time

func (m model) fetchStatus() tea.Msg {
	status, err := m.client.AdminClusterStatus(context.Background())
	if err != nil {
		return errMsg(err)
	}
	return statusMsg(status)
}

func (m model) fetchUsers() tea.Msg {
	users, err := m.client.AdminListUsers(context.Background())
	if err != nil {
		return errMsg(err)
	}
	return usersMsg(users)
}

func (m model) fetchNodes() tea.Msg {
	nodes, err := m.client.AdminListNodes(context.Background())
	if err != nil {
		return errMsg(err)
	}
	return nodesMsg(nodes)
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

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
			m.tab = tabNodes
		case "4":
			m.tab = tabTools
			m.lookupInput.Focus()
		case "tab":
			m.tab = (m.tab + 1) % 4
			if m.tab == tabTools {
				m.lookupInput.Focus()
			}
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
	case nodesMsg:
		m.nodes = msg
		m.updateNodeTable()
	case lookupMsg:
		m.lookupResult = string(msg)
	case tickMsg:
		return m, tea.Batch(m.fetchStatus, m.fetchUsers, m.fetchNodes, tea.Tick(2*time.Second, func(t time.Time) tea.Msg {
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
					id, err := m.client.AdminLookup(context.Background(), email)
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
			quota = formatBytes(u.Quota.MaxBytes)
		}
		rows = append(rows, table.Row{
			u.ID,
			fmt.Sprintf("%d", u.Usage.InodeCount),
			formatBytes(u.Usage.TotalBytes),
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
		return fmt.Sprintf("\n  Error: %v\n\n  Press q to quit.", m.err)
	}

	doc := strings.Builder{}

	// Tabs
	var tabs []string
	titles := []string{"1. Overview", "2. Users", "3. Nodes", "4. Tools"}
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
	case tabNodes:
		content = m.nodeTable.View()
	case tabTools:
		content = m.toolsView()
	}

	doc.WriteString(windowStyle.Render(content))
	doc.WriteString("\n  (q: quit, 1-4: tabs, tab: next)\n")

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

	return lipgloss.JoinVertical(lipgloss.Left,
		titleStyle.Render("Cluster Status"),
		fmt.Sprintf("State:  %s", state),
		fmt.Sprintf("Leader: %s", leader),
		fmt.Sprintf("Commit: %s", commit),
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

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func cmdAdmin(args []string) {
	c := loadClient()

	ti := textinput.New()
	ti.Placeholder = "user@example.com"
	ti.CharLimit = 156
	ti.Width = 40

	m := model{
		client:      c,
		tab:         tabOverview,
		lookupInput: ti,
	}

	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		log.Fatal(err)
	}
}

func cmdAdminJoin(args []string) {
	if len(args) < 1 {
		log.Fatal("node address required (e.g. http://node-2:8080)")
	}
	address := args[0]
	c := loadClient()
	if err := c.AdminJoinNode(context.Background(), address); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Join request for %s submitted to cluster.\n", address)
}

func cmdAdminChown(args []string) {
	if len(args) < 2 {
		log.Fatal("usage: admin-chown <email>[:<group_id>] <path>")
	}
	ownerSpec, path := args[0], args[1]
	c := loadClient()

	var req metadata.AdminChownRequest
	parts := strings.Split(ownerSpec, ":")
	email := parts[0]

	// 1. Resolve email to UserID
	userID, err := c.AdminLookup(context.Background(), email)
	if err != nil {
		log.Fatalf("failed to resolve email %s: %v", email, err)
	}
	req.OwnerID = &userID

	// 2. Resolve Group if provided
	if len(parts) > 1 {
		groupID := parts[1]
		req.GroupID = &groupID
	}

	// 3. Resolve Path to InodeID
	inode, _, err := c.ResolvePath(path)
	if err != nil {
		log.Fatalf("failed to resolve path %s: %v", path, err)
	}

	// 4. Warning
	fmt.Printf("WARNING: Changing ownership of %s to %s.\n", path, email)
	fmt.Println("Existing encrypted data will NOT be readable by the new owner.")
	fmt.Print("Proceed? [y/N]: ")
	var confirm string
	fmt.Scanln(&confirm)
	if strings.ToLower(confirm) != "y" {
		fmt.Println("Aborted.")
		return
	}

	if err := c.AdminChown(context.Background(), inode.ID, req); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Ownership updated successfully.")
}

func cmdAdminChmod(args []string) {
	if len(args) < 2 {
		log.Fatal("usage: admin-chmod <mode> <path>")
	}
	modeStr, path := args[0], args[1]
	mode, err := strconv.ParseUint(modeStr, 8, 32)
	if err != nil {
		log.Fatalf("invalid mode: %v", err)
	}

	c := loadClient()
	inode, _, err := c.ResolvePath(path)
	if err != nil {
		log.Fatalf("failed to resolve path %s: %v", path, err)
	}

	fmt.Printf("WARNING: Overriding permissions of %s to %s.\n", path, modeStr)
	fmt.Println("This only affects metadata visibility.")
	fmt.Print("Proceed? [y/N]: ")
	var confirm string
	fmt.Scanln(&confirm)
	if strings.ToLower(confirm) != "y" {
		fmt.Println("Aborted.")
		return
	}

	if err := c.AdminChmod(context.Background(), inode.ID, uint32(mode)); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Permissions updated successfully.")
}
