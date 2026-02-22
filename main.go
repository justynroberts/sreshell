// MIT License - Copyright (c) fintonlabs.com
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/gdamore/tcell/v2"
)

// PagerDuty API types
type Incident struct {
	ID          string `json:"id"`
	IncidentNum int    `json:"incident_number"`
	Title       string `json:"title"`
	Status      string `json:"status"`
	Urgency     string `json:"urgency"`
	CreatedAt   string `json:"created_at"`
	Service     struct {
		Summary string `json:"summary"`
	} `json:"service"`
}

type IncidentsResponse struct {
	Incidents []Incident `json:"incidents"`
}

type NoteRequest struct {
	Note struct {
		Content string `json:"content"`
	} `json:"note"`
}

type SREAgentRequest struct {
	IncidentID string `json:"incident_id"`
	Query      string `json:"query"`
}

type SREAgentResponse struct {
	Response string `json:"response"`
	Error    string `json:"error,omitempty"`
}

// Application state
type App struct {
	screen       tcell.Screen
	apiToken     string
	baseURL      string
	incident     *Incident
	shellCmd     *exec.Cmd
	shellPty     *os.File
	shellOutput  []string
	sreOutput    []string
	shellScroll  int
	sreScroll    int
	inputBuffer  string
	inputMode    string // "shell" or "sre"
	cursorPos    int
	width        int
	height       int
	mu           sync.Mutex
	cmdBuffer    strings.Builder
	outputBuffer strings.Builder
	noteQueue    []string
	noteMu       sync.Mutex
	quit         chan struct{}
	// Command history
	cmdHistory    []string
	historyIdx    int
	historyTmp    string // stores current input when navigating history
	// SRE suggested commands (for !N copy feature)
	sreCommands   []string
}

func main() {
	token := strings.TrimSpace(os.Getenv("PAGERDUTY_TOKEN"))
	if token == "" {
		fmt.Println("Error: PAGERDUTY_TOKEN environment variable required")
		os.Exit(1)
	}
	// Strip quotes and common mistakes
	token = strings.Trim(token, "\"'`")
	token = strings.TrimPrefix(token, "token=")
	token = strings.TrimPrefix(token, "Token token=")

	// Support EU region
	baseURL := "https://api.pagerduty.com"
	if os.Getenv("PAGERDUTY_REGION") == "eu" {
		baseURL = "https://api.eu.pagerduty.com"
	}

	app := &App{
		apiToken:  token,
		baseURL:   baseURL,
		inputMode: "shell",
		quit:      make(chan struct{}),
	}

	// Fetch and select incident
	incident, err := app.selectIncident()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	app.incident = incident

	// Initialize screen
	screen, err := tcell.NewScreen()
	if err != nil {
		fmt.Printf("Error creating screen: %v\n", err)
		os.Exit(1)
	}
	if err := screen.Init(); err != nil {
		fmt.Printf("Error initializing screen: %v\n", err)
		os.Exit(1)
	}
	app.screen = screen
	app.width, app.height = screen.Size()

	// Start shell
	if err := app.startShell(); err != nil {
		screen.Fini()
		fmt.Printf("Error starting shell: %v\n", err)
		os.Exit(1)
	}

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGWINCH, syscall.SIGINT, syscall.SIGTERM)
	go app.handleSignals(sigCh)

	// Start note flusher
	go app.noteFlushLoop()

	// Add initial note
	app.queueNote(fmt.Sprintf("=== Troubleshooting session started ===\nIncident: %s\nTime: %s",
		app.incident.Title, time.Now().Format(time.RFC3339)))

	// Initial SRE agent query - run analysis
	go func() {
		app.addSREOutput("Running incident analysis...")
		resp, err := app.querySREAgent(fmt.Sprintf("run analysis for incident %s", app.incident.ID))
		if err != nil {
			app.addSREOutput(fmt.Sprintf("Error: %v", err))
		} else {
			app.addSREOutput(resp)
		}
		app.draw()
	}()

	// Main event loop
	app.run()

	// Cleanup
	app.shellPty.Close()
	app.shellCmd.Process.Kill()
	screen.Fini()

	// Flush remaining notes
	app.flushNotes()
	fmt.Println("Session ended. Notes saved to incident.")
}

func (app *App) selectIncident() (*Incident, error) {
	fmt.Println("Fetching open incidents from PagerDuty...")
	fmt.Printf("API: %s\n", app.baseURL)
	fmt.Printf("Token: %d chars, prefix: %s...\n", len(app.apiToken), safePrefix(app.apiToken, 4))

	req, err := http.NewRequest("GET", app.baseURL+"/incidents?statuses[]=triggered&statuses[]=acknowledged&limit=20", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Token token="+app.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		if len(body) == 0 {
			return nil, fmt.Errorf("API error %d (no response body)\nCheck: https://support.pagerduty.com/main/docs/api-access-keys", resp.StatusCode)
		}
		return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	var incResp IncidentsResponse
	if err := json.NewDecoder(resp.Body).Decode(&incResp); err != nil {
		return nil, err
	}

	if len(incResp.Incidents) == 0 {
		return nil, fmt.Errorf("no open incidents found")
	}

	fmt.Println("\nOpen Incidents:")
	fmt.Println(strings.Repeat("-", 80))
	for i, inc := range incResp.Incidents {
		status := "T"
		if inc.Status == "acknowledged" {
			status = "A"
		}
		fmt.Printf("[%d] #%d [%s] %s\n    Service: %s\n",
			i+1, inc.IncidentNum, status, inc.Title, inc.Service.Summary)
	}
	fmt.Println(strings.Repeat("-", 80))

	var choice int
	for {
		fmt.Print("Select incident (1-", len(incResp.Incidents), ") or 'q' to quit: ")
		var input string
		fmt.Scanf("%s", &input)
		if input == "q" || input == "quit" || input == "exit" {
			return nil, fmt.Errorf("user cancelled")
		}
		if num, err := parseNumber(input); err == nil && num >= 1 && num <= len(incResp.Incidents) {
			choice = num
			break
		}
		fmt.Println("Invalid selection, try again.")
	}

	selected := &incResp.Incidents[choice-1]
	fmt.Printf("\nSelected: #%d - %s\n", selected.IncidentNum, selected.Title)
	fmt.Println("Starting troubleshooting shell...\n")
	time.Sleep(500 * time.Millisecond)

	return selected, nil
}

func (app *App) startShell() error {
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/bash"
	}

	app.shellCmd = exec.Command(shell)
	app.shellCmd.Env = append(os.Environ(),
		fmt.Sprintf("PAGERDUTY_INCIDENT=%s", app.incident.ID),
		fmt.Sprintf("PAGERDUTY_INCIDENT_NUM=%d", app.incident.IncidentNum),
	)

	var err error
	app.shellPty, err = pty.Start(app.shellCmd)
	if err != nil {
		return err
	}

	// Read shell output
	go app.readShellOutput()

	return nil
}

func (app *App) readShellOutput() {
	buf := make([]byte, 4096)
	for {
		n, err := app.shellPty.Read(buf)
		if err != nil {
			return
		}
		if n > 0 {
			app.mu.Lock()
			output := string(buf[:n])
			app.outputBuffer.WriteString(output)

			// Process output for display (handle ANSI codes minimally)
			lines := strings.Split(output, "\n")
			for i, line := range lines {
				if i == 0 && len(app.shellOutput) > 0 {
					app.shellOutput[len(app.shellOutput)-1] += line
				} else {
					app.shellOutput = append(app.shellOutput, line)
				}
			}

			// Keep buffer manageable
			if len(app.shellOutput) > 1000 {
				app.shellOutput = app.shellOutput[len(app.shellOutput)-500:]
			}
			app.mu.Unlock()
			app.draw()
		}
	}
}

func (app *App) handleSignals(sigCh chan os.Signal) {
	for sig := range sigCh {
		switch sig {
		case syscall.SIGWINCH:
			app.screen.Sync()
			app.width, app.height = app.screen.Size()
			pty.Setsize(app.shellPty, &pty.Winsize{
				Rows: uint16(app.height - 3),
				Cols: uint16(app.width/2 - 1),
			})
			app.draw()
		case syscall.SIGINT, syscall.SIGTERM:
			close(app.quit)
			return
		}
	}
}

func (app *App) run() {
	for {
		select {
		case <-app.quit:
			return
		default:
		}

		ev := app.screen.PollEvent()
		switch ev := ev.(type) {
		case *tcell.EventResize:
			app.width, app.height = ev.Size()
			app.screen.Sync()
			pty.Setsize(app.shellPty, &pty.Winsize{
				Rows: uint16(app.height - 3),
				Cols: uint16(app.width/2 - 1),
			})
			app.draw()

		case *tcell.EventKey:
			if ev.Key() == tcell.KeyCtrlC && ev.Modifiers()&tcell.ModAlt != 0 {
				// Alt+Ctrl+C to quit
				close(app.quit)
				return
			}

			if ev.Key() == tcell.KeyTab {
				// Toggle between shell and SRE input
				if app.inputMode == "shell" {
					app.inputMode = "sre"
				} else {
					app.inputMode = "shell"
				}
				app.inputBuffer = ""
				app.cursorPos = 0
				app.draw()
				continue
			}

			if app.inputMode == "shell" {
				app.handleShellInput(ev)
			} else {
				app.handleSREInput(ev)
			}
		}
	}
}

func (app *App) handleShellInput(ev *tcell.EventKey) {
	switch ev.Key() {
	case tcell.KeyEnter:
		cmd := strings.TrimSpace(app.inputBuffer)

		// Check for special commands
		if cmd == "!q" || cmd == "!quit" || cmd == "!exit" {
			close(app.quit)
			return
		}

		// Check for !N pattern to copy SRE command
		if strings.HasPrefix(cmd, "!") && len(cmd) > 1 {
			numStr := cmd[1:]
			if num, err := parseNumber(numStr); err == nil && num >= 1 && num <= len(app.sreCommands) {
				// Copy command from SRE suggestions
				app.inputBuffer = app.sreCommands[num-1]
				app.cursorPos = len(app.inputBuffer)
				app.draw()
				return
			}
		}

		// Add to history if non-empty and different from last
		if cmd != "" {
			if len(app.cmdHistory) == 0 || app.cmdHistory[len(app.cmdHistory)-1] != cmd {
				app.cmdHistory = append(app.cmdHistory, cmd)
				// Keep history manageable
				if len(app.cmdHistory) > 500 {
					app.cmdHistory = app.cmdHistory[len(app.cmdHistory)-250:]
				}
			}
		}
		app.historyIdx = len(app.cmdHistory)
		app.historyTmp = ""

		// Log command before sending
		if cmd != "" {
			app.cmdBuffer.WriteString(cmd + "\n")
		}
		app.shellPty.WriteString(app.inputBuffer + "\n")
		app.inputBuffer = ""
		app.cursorPos = 0

		// After a delay, capture output for notes
		go func(command string) {
			time.Sleep(500 * time.Millisecond)
			app.mu.Lock()
			output := app.outputBuffer.String()
			app.outputBuffer.Reset()
			app.mu.Unlock()

			if command != "" || output != "" {
				note := fmt.Sprintf("$ %s\n%s", command, output)
				app.queueNote(note)
			}
		}(cmd)

	case tcell.KeyBackspace, tcell.KeyBackspace2:
		if app.cursorPos > 0 {
			app.inputBuffer = app.inputBuffer[:app.cursorPos-1] + app.inputBuffer[app.cursorPos:]
			app.cursorPos--
		}
	case tcell.KeyDelete:
		if app.cursorPos < len(app.inputBuffer) {
			app.inputBuffer = app.inputBuffer[:app.cursorPos] + app.inputBuffer[app.cursorPos+1:]
		}
	case tcell.KeyLeft:
		if app.cursorPos > 0 {
			app.cursorPos--
		}
	case tcell.KeyRight:
		if app.cursorPos < len(app.inputBuffer) {
			app.cursorPos++
		}
	case tcell.KeyUp:
		// Navigate command history (up = older)
		if len(app.cmdHistory) > 0 {
			if app.historyIdx == len(app.cmdHistory) {
				// Save current input before navigating
				app.historyTmp = app.inputBuffer
			}
			if app.historyIdx > 0 {
				app.historyIdx--
				app.inputBuffer = app.cmdHistory[app.historyIdx]
				app.cursorPos = len(app.inputBuffer)
			}
		}
	case tcell.KeyDown:
		// Navigate command history (down = newer)
		if app.historyIdx < len(app.cmdHistory) {
			app.historyIdx++
			if app.historyIdx == len(app.cmdHistory) {
				// Restore saved input
				app.inputBuffer = app.historyTmp
			} else {
				app.inputBuffer = app.cmdHistory[app.historyIdx]
			}
			app.cursorPos = len(app.inputBuffer)
		}
	case tcell.KeyCtrlC:
		app.shellPty.Write([]byte{0x03})
	case tcell.KeyCtrlD:
		app.shellPty.Write([]byte{0x04})
	case tcell.KeyCtrlZ:
		app.shellPty.Write([]byte{0x1a})
	case tcell.KeyCtrlL:
		app.shellPty.Write([]byte{0x0c})
	case tcell.KeyCtrlR:
		// Reverse search - show history hint
		app.addSREOutput("History search: use Up/Down arrows or !N to copy SRE command")
	default:
		if ev.Rune() != 0 {
			app.inputBuffer = app.inputBuffer[:app.cursorPos] + string(ev.Rune()) + app.inputBuffer[app.cursorPos:]
			app.cursorPos++
		}
	}
	app.draw()
}

func (app *App) handleSREInput(ev *tcell.EventKey) {
	switch ev.Key() {
	case tcell.KeyEnter:
		query := strings.TrimSpace(app.inputBuffer)

		// Check for quit commands
		if query == "!q" || query == "!quit" || query == "!exit" {
			close(app.quit)
			return
		}

		// Check for shortcut commands
		if query == "!next" || query == "!n" {
			query = fmt.Sprintf("what are my next steps for incident %s", app.incident.ID)
		}

		if query != "" {
			app.addSREOutput(fmt.Sprintf("> %s", query))
			app.addSREOutput("Thinking...")
			app.inputBuffer = ""
			app.cursorPos = 0
			app.draw()

			go func(q string) {
				resp, err := app.querySREAgent(q)
				// Remove "Thinking..."
				app.mu.Lock()
				if len(app.sreOutput) > 0 {
					app.sreOutput = app.sreOutput[:len(app.sreOutput)-1]
				}
				app.mu.Unlock()

				if err != nil {
					app.addSREOutput(fmt.Sprintf("Error: %v", err))
				} else {
					app.addSREOutput(resp)
				}
				app.draw()
			}(query)
		}
	case tcell.KeyCtrlN:
		// Shortcut for "what are my next steps"
		app.addSREOutput("> what are my next steps?")
		app.addSREOutput("Thinking...")
		app.draw()
		go func() {
			resp, err := app.querySREAgent(fmt.Sprintf("what are my next steps for incident %s", app.incident.ID))
			app.mu.Lock()
			if len(app.sreOutput) > 0 {
				app.sreOutput = app.sreOutput[:len(app.sreOutput)-1]
			}
			app.mu.Unlock()
			if err != nil {
				app.addSREOutput(fmt.Sprintf("Error: %v", err))
			} else {
				app.addSREOutput(resp)
			}
			app.draw()
		}()
	case tcell.KeyBackspace, tcell.KeyBackspace2:
		if app.cursorPos > 0 {
			app.inputBuffer = app.inputBuffer[:app.cursorPos-1] + app.inputBuffer[app.cursorPos:]
			app.cursorPos--
		}
	case tcell.KeyLeft:
		if app.cursorPos > 0 {
			app.cursorPos--
		}
	case tcell.KeyRight:
		if app.cursorPos < len(app.inputBuffer) {
			app.cursorPos++
		}
	default:
		if ev.Rune() != 0 {
			app.inputBuffer = app.inputBuffer[:app.cursorPos] + string(ev.Rune()) + app.inputBuffer[app.cursorPos:]
			app.cursorPos++
		}
	}
	app.draw()
}

func (app *App) draw() {
	app.mu.Lock()
	defer app.mu.Unlock()

	app.screen.Clear()
	w, h := app.width, app.height
	midX := w / 2

	style := tcell.StyleDefault
	borderStyle := tcell.StyleDefault.Foreground(tcell.ColorGray)
	headerStyle := tcell.StyleDefault.Bold(true).Foreground(tcell.ColorYellow)
	activeStyle := tcell.StyleDefault.Bold(true).Foreground(tcell.ColorGreen)
	statusStyle := tcell.StyleDefault.Foreground(tcell.ColorTeal)

	// Draw vertical divider
	for y := 0; y < h-2; y++ {
		app.screen.SetContent(midX, y, tcell.RuneVLine, nil, borderStyle)
	}

	// Draw headers
	shellHeader := " Shell "
	sreHeader := " SRE Agent "
	if app.inputMode == "shell" {
		app.drawString(1, 0, shellHeader, activeStyle)
		app.drawString(midX+2, 0, sreHeader, headerStyle)
	} else {
		app.drawString(1, 0, shellHeader, headerStyle)
		app.drawString(midX+2, 0, sreHeader, activeStyle)
	}

	// Draw horizontal line under headers
	for x := 0; x < midX; x++ {
		app.screen.SetContent(x, 1, tcell.RuneHLine, nil, borderStyle)
	}
	for x := midX + 1; x < w; x++ {
		app.screen.SetContent(x, 1, tcell.RuneHLine, nil, borderStyle)
	}
	app.screen.SetContent(midX, 1, tcell.RuneTTee, nil, borderStyle)

	// Draw shell output (left pane)
	shellHeight := h - 4
	startLine := 0
	if len(app.shellOutput) > shellHeight {
		startLine = len(app.shellOutput) - shellHeight
	}
	for i, line := range app.shellOutput[startLine:] {
		y := 2 + i
		if y >= h-2 {
			break
		}
		// Strip ANSI codes for display
		cleaned := stripANSI(line)
		if len(cleaned) > midX-1 {
			cleaned = cleaned[:midX-1]
		}
		app.drawString(0, y, cleaned, style)
	}

	// Draw SRE output (right pane)
	sreHeight := h - 4
	startSRE := 0
	if len(app.sreOutput) > sreHeight {
		startSRE = len(app.sreOutput) - sreHeight
	}
	for i, line := range app.sreOutput[startSRE:] {
		y := 2 + i
		if y >= h-2 {
			break
		}
		// Word wrap for SRE pane
		maxWidth := w - midX - 3
		wrapped := wrapText(line, maxWidth)
		for j, wline := range wrapped {
			if y+j >= h-2 {
				break
			}
			app.drawString(midX+2, y+j, wline, style)
		}
	}

	// Draw bottom status bar
	statusY := h - 2
	for x := 0; x < w; x++ {
		app.screen.SetContent(x, statusY, tcell.RuneHLine, nil, borderStyle)
	}

	incStatus := fmt.Sprintf(" INC#%d: %s ", app.incident.IncidentNum, truncate(app.incident.Title, 40))
	app.drawString(1, statusY, incStatus, statusStyle)

	app.noteMu.Lock()
	noteCount := len(app.noteQueue)
	app.noteMu.Unlock()
	noteStatus := fmt.Sprintf("[Notes queued: %d]", noteCount)
	app.drawString(w-len(noteStatus)-2, statusY, noteStatus, statusStyle)

	// Draw input line
	inputY := h - 1
	var prompt string
	if app.inputMode == "shell" {
		prompt = "$ "
	} else {
		prompt = "ask> "
	}
	app.drawString(0, inputY, prompt, activeStyle)
	app.drawString(len(prompt), inputY, app.inputBuffer, style)

	// Show cursor
	app.screen.ShowCursor(len(prompt)+app.cursorPos, inputY)

	// Help text
	var helpText string
	if app.inputMode == "shell" {
		helpText = "[Tab: pane] [Up/Down: history] [!N: copy] [!q: quit]"
	} else {
		helpText = "[Tab: pane] [Ctrl+N: next steps] [!n: next] [!q: quit]"
	}
	if len(helpText) > w-len(prompt)-len(app.inputBuffer)-2 {
		helpText = "[Tab] [!q]"
	}
	app.drawString(w-len(helpText)-1, inputY, helpText, tcell.StyleDefault.Foreground(tcell.ColorDarkGray))

	app.screen.Show()
}

func (app *App) drawString(x, y int, s string, style tcell.Style) {
	for i, r := range s {
		if x+i >= app.width {
			break
		}
		app.screen.SetContent(x+i, y, r, nil, style)
	}
}

func (app *App) addSREOutput(text string) {
	app.mu.Lock()
	defer app.mu.Unlock()

	// Clean the text before displaying
	clean := toASCII(stripANSI(text))
	lines := strings.Split(clean, "\n")
	app.sreOutput = append(app.sreOutput, lines...)

	// Keep buffer manageable
	if len(app.sreOutput) > 500 {
		app.sreOutput = app.sreOutput[len(app.sreOutput)-250:]
	}
}

// MCP JSON-RPC request/response types
type MCPRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int         `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
}

type MCPToolCall struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments"`
}

type MCPResponse struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Result  struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	} `json:"result"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (app *App) querySREAgent(query string) (string, error) {
	mcpResponse, err := app.callAdvanceMCP(query)
	if err != nil {
		return "", err
	}
	return app.formatMCPResponse(mcpResponse, query), nil
}

func (app *App) callAdvanceMCP(message string) (string, error) {
	// PagerDuty Advance MCP endpoint (different from main MCP)
	mcpURL := "https://mcp.pagerduty.com/pagerduty-advance-mcp"

	// Build MCP tool call request
	toolCall := MCPToolCall{
		Name: "sre_agent_tool",
		Arguments: map[string]interface{}{
			"incident_id": app.incident.ID,
			"message":     message,
		},
	}

	mcpReq := MCPRequest{
		JSONRPC: "2.0",
		ID:      int(time.Now().UnixMilli()),
		Method:  "tools/call",
		Params:  toolCall,
	}

	body, err := json.Marshal(mcpReq)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", mcpURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Token token="+app.apiToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	// SRE agent requires user identification
	fromEmail := os.Getenv("PAGERDUTY_EMAIL")
	if fromEmail != "" {
		req.Header.Set("From", fromEmail)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("MCP error %d: %s", resp.StatusCode, string(respBody))
	}

	var mcpResp MCPResponse
	if err := json.NewDecoder(resp.Body).Decode(&mcpResp); err != nil {
		return "", err
	}

	if mcpResp.Error != nil {
		return "", fmt.Errorf("MCP error: %s", mcpResp.Error.Message)
	}

	// Extract text content from response
	var result strings.Builder
	for _, content := range mcpResp.Result.Content {
		if content.Type == "text" {
			result.WriteString(content.Text)
			result.WriteString("\n")
		}
	}

	return result.String(), nil
}

func (app *App) formatMCPResponse(response string, query string) string {
	var result strings.Builder
	var commands []string

	result.WriteString(response)
	result.WriteString("\n")

	// Extract commands from response (lines starting with $ or common command patterns)
	lines := strings.Split(response, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "$ ") {
			commands = append(commands, strings.TrimPrefix(line, "$ "))
		} else if strings.HasPrefix(line, "kubectl ") ||
			strings.HasPrefix(line, "docker ") ||
			strings.HasPrefix(line, "curl ") ||
			strings.HasPrefix(line, "systemctl ") {
			commands = append(commands, line)
		}
	}

	// If we found commands, number them
	if len(commands) > 0 {
		result.WriteString("\nExtracted commands:\n")
		for i, cmd := range commands {
			if i >= 10 {
				break
			}
			result.WriteString(fmt.Sprintf("  [%d] %s\n", i+1, cmd))
		}
		result.WriteString("\nType !N in shell to copy command N")
	}

	// Store commands for !N feature
	app.mu.Lock()
	app.sreCommands = commands
	app.mu.Unlock()

	return result.String()
}

func (app *App) queueNote(content string) {
	// Clean content: strip ANSI codes and convert to ASCII only
	clean := toASCII(stripANSI(content))
	if strings.TrimSpace(clean) == "" {
		return
	}
	app.noteMu.Lock()
	defer app.noteMu.Unlock()
	app.noteQueue = append(app.noteQueue, clean)
}

func (app *App) noteFlushLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-app.quit:
			return
		case <-ticker.C:
			app.flushNotes()
		}
	}
}

func (app *App) flushNotes() {
	app.noteMu.Lock()
	if len(app.noteQueue) == 0 {
		app.noteMu.Unlock()
		return
	}

	// Combine all queued notes
	combined := strings.Join(app.noteQueue, "\n---\n")
	count := len(app.noteQueue)
	app.noteQueue = nil
	app.noteMu.Unlock()

	// Truncate if too long
	if len(combined) > 25000 {
		combined = combined[:25000] + "\n[truncated]"
	}

	// Post to PagerDuty
	noteReq := NoteRequest{}
	noteReq.Note.Content = combined

	body, _ := json.Marshal(noteReq)
	url := fmt.Sprintf("%s/incidents/%s/notes", app.baseURL, app.incident.ID)

	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		app.addSREOutput(fmt.Sprintf("[Note error: %v]", err))
		return
	}
	req.Header.Set("Authorization", "Token token="+app.apiToken)
	req.Header.Set("Content-Type", "application/json")
	// From header required - use PAGERDUTY_EMAIL env var or default
	fromEmail := os.Getenv("PAGERDUTY_EMAIL")
	if fromEmail == "" {
		fromEmail = "tshell@local"
	}
	req.Header.Set("From", fromEmail)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		app.addSREOutput(fmt.Sprintf("[Note error: %v]", err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		respBody, _ := io.ReadAll(resp.Body)
		app.addSREOutput(fmt.Sprintf("[Note failed %d: %s]", resp.StatusCode, string(respBody)))
	} else {
		app.addSREOutput(fmt.Sprintf("[Saved %d notes to incident]", count))
	}
}

// Helper functions

func stripANSI(s string) string {
	var result strings.Builder
	inEscape := false
	inCSI := false
	inOSC := false
	for _, r := range s {
		// Start of escape sequence
		if r == '\x1b' {
			inEscape = true
			continue
		}
		// Handle escape sequences
		if inEscape {
			if r == '[' {
				inCSI = true
				continue
			}
			if r == ']' {
				inOSC = true // Operating System Command (title, etc)
				continue
			}
			if inOSC {
				// OSC ends with BEL (\x07) or ST (\x1b\\)
				if r == '\x07' {
					inEscape = false
					inOSC = false
				}
				continue
			}
			if inCSI {
				// CSI sequence ends with a letter
				if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
					inEscape = false
					inCSI = false
				}
				continue
			}
			// Non-CSI escape sequence ends with letter
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				inEscape = false
			}
			continue
		}
		// Skip other control characters
		if r < 32 && r != '\n' && r != '\t' {
			continue
		}
		result.WriteRune(r)
	}
	return result.String()
}

func toASCII(s string) string {
	var result strings.Builder
	for _, r := range s {
		// Keep printable ASCII and common whitespace
		if (r >= 32 && r <= 126) || r == '\n' || r == '\t' {
			result.WriteRune(r)
		} else if r == '\r' {
			// Skip carriage returns
			continue
		}
	}
	return result.String()
}

func wrapText(s string, width int) []string {
	if width <= 0 {
		return []string{s}
	}
	var lines []string
	for len(s) > width {
		// Find last space within width
		idx := strings.LastIndex(s[:width], " ")
		if idx <= 0 {
			idx = width
		}
		lines = append(lines, s[:idx])
		s = strings.TrimLeft(s[idx:], " ")
	}
	if len(s) > 0 {
		lines = append(lines, s)
	}
	return lines
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func parseNumber(s string) (int, error) {
	var n int
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("not a number")
		}
		n = n*10 + int(r-'0')
	}
	return n, nil
}

func safePrefix(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
