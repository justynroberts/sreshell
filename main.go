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
		ID      string `json:"id"`
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
	userID       string
	userEmail    string
	incident     *Incident
	sessionID    string // SRE agent session - persists per incident
	shellCmd     *exec.Cmd
	shellPty     *os.File
	shellOutput  []string
	sreOutput    []string
	shellScroll  int // lines scrolled up from bottom
	sreScroll    int // lines scrolled up from bottom
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
	cmdHistory []string
	historyIdx int
	historyTmp string // stores current input when navigating history
	// Cached data for on-demand display
	pastIncidentsCache string
	fullAnalysisCache  string
	// Help popup
	showHelp bool
	// Status message (shown briefly below input)
	statusMsg     string
	statusMsgTime time.Time
	// Tmux session name for shell
	tmuxSession string
	// Mouse selection state
	selecting    bool
	selStartX    int
	selStartY    int
	selEndX      int
	selEndY      int
	selPane      string // "shell" or "sre" - which pane selection started in
}

func main() {
	// Prefer PAGERDUTY_USER_TOKEN (user token), fall back to PAGERDUTY_TOKEN
	token := strings.TrimSpace(os.Getenv("PAGERDUTY_USER_TOKEN"))
	if token == "" {
		token = strings.TrimSpace(os.Getenv("PAGERDUTY_TOKEN"))
	}
	if token == "" {
		fmt.Println("Error: PAGERDUTY_USER_TOKEN or PAGERDUTY_TOKEN environment variable required")
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
	}

	// Fetch current user ID for SRE agent
	if err := app.fetchCurrentUser(); err != nil {
		fmt.Printf("Warning: Could not fetch user: %v\n", err)
	}

	// Main loop - select incident and run session
	for {
		// Reset state for new session
		app.quit = make(chan struct{})
		app.shellOutput = nil
		app.sreOutput = nil
		app.shellScroll = 0
		app.sreScroll = 0
		app.inputBuffer = ""
		app.cursorPos = 0
		app.inputMode = "shell"
		app.pastIncidentsCache = ""
		app.fullAnalysisCache = ""
		app.showHelp = false

		// Fetch and select incident
		incident, err := app.selectIncident()
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		if incident == nil {
			// User quit
			fmt.Println("Goodbye!")
			os.Exit(0)
		}
		app.incident = incident
		app.sessionID = fmt.Sprintf("%s-%s", app.userID, incident.ID)

		// Run session for this incident
		app.runIncidentSession()
	}
}

func (app *App) runIncidentSession() {
	// Initialize screen
	screen, err := tcell.NewScreen()
	if err != nil {
		fmt.Printf("Error creating screen: %v\n", err)
		return
	}
	if err := screen.Init(); err != nil {
		fmt.Printf("Error initializing screen: %v\n", err)
		return
	}
	// Mouse disabled - allows native terminal selection/copy
	// Use keyboard for scrolling (Up/Down, PgUp/PgDn)
	app.screen = screen
	app.width, app.height = screen.Size()

	// Start shell
	if err := app.startShell(); err != nil {
		screen.Fini()
		fmt.Printf("Error starting shell: %v\n", err)
		return
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

	// Initial SRE agent query - gather context first, then run analysis
	go func() {
		// Clear debug file
		os.WriteFile("sre_output.txt", []byte{}, 0644)

		// Header with full title
		app.addSREOutput(fmt.Sprintf("#%d | %s | %s", app.incident.IncidentNum, app.incident.Status, app.incident.Service.Summary))
		app.addSREOutput(app.incident.Title)
		app.addSREOutput("")
		app.draw()

		// Get recent changes
		app.addSREOutput("RECENT CHANGES:")
		app.draw()
		recentChanges, _ := app.callStandardMCP("list_change_events", map[string]interface{}{
			"query_model": map[string]interface{}{
				"limit": 3,
			},
		})
		if recentChanges != "" {
			formatted := formatChanges(recentChanges)
			if formatted != "" {
				app.addSREOutput(formatted)
			} else {
				app.addSREOutput("  (none)")
			}
		} else {
			app.addSREOutput("  (none)")
		}
		app.draw()

		// Get incident details (for context, not display)
		details, _ := app.callStandardMCP("get_incident", map[string]interface{}{
			"incident_id": app.incident.ID,
		})

		// Get related/past incidents from same service
		app.addSREOutput("")
		app.addSREOutput("RELATED INCIDENTS:")
		app.draw()
		pastIncidents, _ := app.callStandardMCP("list_incidents", map[string]interface{}{
			"query_model": map[string]interface{}{
				"status":      "resolved",
				"service_ids": []string{app.incident.Service.ID},
				"limit":       3,
			},
		})
		if pastIncidents != "" {
			formatted := formatIncidentsCompact(pastIncidents)
			if formatted != "" {
				app.addSREOutput(formatted)
			} else {
				app.addSREOutput("  (none)")
			}
		} else {
			app.addSREOutput("  (none)")
		}
		// Store for !h command
		app.mu.Lock()
		app.pastIncidentsCache = pastIncidents
		app.mu.Unlock()

		app.addSREOutput("")
		app.draw()

		// Build triage request for SRE agent
		var context strings.Builder
		context.WriteString(fmt.Sprintf("Triage incident %s.\n\n", app.incident.ID))
		if details != "" {
			context.WriteString("Incident Details:\n")
			context.WriteString(details)
			context.WriteString("\n\n")
		}
		if recentChanges != "" {
			context.WriteString("Recent Changes:\n")
			context.WriteString(recentChanges)
			context.WriteString("\n\n")
		}
		context.WriteString("Provide:\n")
		context.WriteString("1. POTENTIAL ROOT CAUSE: One paragraph on the likely cause\n")
		context.WriteString("2. NEXT STEPS: Numbered list of 3-5 diagnostic/remediation steps\n")
		context.WriteString("Be concise and actionable.")

		app.addSREOutput("")
		app.addSREOutput("Running SRE analysis...")
		app.draw()

		// Show progress while waiting for SRE response
		done := make(chan bool)
		go func() {
			dots := 0
			for {
				select {
				case <-done:
					return
				case <-time.After(1 * time.Second):
					dots++
					app.mu.Lock()
					if len(app.sreOutput) > 0 {
						// Update the last line with progress
						app.sreOutput[len(app.sreOutput)-1] = fmt.Sprintf("Running SRE analysis%s (%ds)", strings.Repeat(".", dots%4), dots)
					}
					app.mu.Unlock()
					app.draw()
				}
			}
		}()

		// Try up to 3 times for transient errors
		var resp string
		var err error
		for attempt := 1; attempt <= 3; attempt++ {
			resp, err = app.querySREAgent(context.String())
			if err == nil {
				break
			}
			if strings.Contains(err.Error(), "Server error") && attempt < 3 {
				app.mu.Lock()
				if len(app.sreOutput) > 0 {
					app.sreOutput[len(app.sreOutput)-1] = fmt.Sprintf("Retrying... (attempt %d/3)", attempt+1)
				}
				app.mu.Unlock()
				app.draw()
				time.Sleep(2 * time.Second)
				continue
			}
			break
		}
		close(done)

		// Clear the progress line
		app.mu.Lock()
		if len(app.sreOutput) > 0 {
			app.sreOutput = app.sreOutput[:len(app.sreOutput)-1]
		}
		app.mu.Unlock()

		if err != nil {
			app.addSREOutput(fmt.Sprintf("Error: %v", err))
		} else if resp == "" {
			app.addSREOutput("(SRE agent returned empty response)")
		} else {
			app.addSREOutput("---")
			app.addSREOutput("TRIAGE:")
			app.addSREOutput(resp)
		}
		app.draw()
	}()

	// Main event loop
	app.run()

	// Cleanup
	if app.shellPty != nil {
		app.shellPty.Close()
	}
	if app.shellCmd != nil && app.shellCmd.Process != nil {
		app.shellCmd.Process.Kill()
		app.shellCmd.Wait() // Prevent zombie process
	}
	// Kill tmux session if we created one
	if app.tmuxSession != "" {
		exec.Command("tmux", "kill-session", "-t", app.tmuxSession).Run()
		app.tmuxSession = ""
	}
	screen.Fini()

	// Clear buffers
	app.cmdBuffer.Reset()
	app.outputBuffer.Reset()

	// Flush remaining notes
	app.flushNotes()
	fmt.Println("\nSession ended. Returning to incident list...")
	time.Sleep(500 * time.Millisecond)
}

func (app *App) fetchCurrentUser() error {
	// First try /users/me (works with user tokens)
	req, err := http.NewRequest("GET", app.baseURL+"/users/me", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Token token="+app.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		var result struct {
			User struct {
				ID    string `json:"id"`
				Email string `json:"email"`
			} `json:"user"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return err
		}
		app.userID = result.User.ID
		app.userEmail = result.User.Email
		return nil
	}

	// Fallback: lookup user by email from PAGERDUTY_EMAIL env var
	email := os.Getenv("PAGERDUTY_EMAIL")
	if email == "" {
		return fmt.Errorf("/users/me failed and PAGERDUTY_EMAIL not set")
	}

	req2, err := http.NewRequest("GET", app.baseURL+"/users?query="+email, nil)
	if err != nil {
		return err
	}
	req2.Header.Set("Authorization", "Token token="+app.apiToken)
	req2.Header.Set("Content-Type", "application/json")

	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		return err
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != 200 {
		body, _ := io.ReadAll(resp2.Body)
		return fmt.Errorf("user lookup failed %d: %s", resp2.StatusCode, string(body))
	}

	var usersResult struct {
		Users []struct {
			ID    string `json:"id"`
			Email string `json:"email"`
		} `json:"users"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&usersResult); err != nil {
		return err
	}

	// Find exact email match
	for _, u := range usersResult.Users {
		if strings.EqualFold(u.Email, email) {
			app.userID = u.ID
			app.userEmail = u.Email
			return nil
		}
	}

	return fmt.Errorf("no user found with email %s", email)
}

func (app *App) selectIncident() (*Incident, error) {

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

	// ANSI colors
	red := "\033[31m"
	yellow := "\033[33m"
	reset := "\033[0m"
	bold := "\033[1m"

	fmt.Println("\n" + bold + "Open Incidents:" + reset)
	fmt.Println(strings.Repeat("-", 60))
	for i, inc := range incResp.Incidents {
		var statusColor, statusText string
		if inc.Status == "triggered" {
			statusColor = red
			statusText = "TRIG"
		} else {
			statusColor = yellow
			statusText = "ACK "
		}
		title := inc.Title
		if len(title) > 50 {
			title = title[:47] + "..."
		}
		fmt.Printf("%s[%d]%s %s%s%s #%d %s\n",
			bold, i+1, reset,
			statusColor, statusText, reset,
			inc.IncidentNum, title)
		fmt.Printf("    %s\n", inc.Service.Summary)
	}
	fmt.Println(strings.Repeat("-", 60))

	var choice int
	for {
		fmt.Print("Select (1-", len(incResp.Incidents), ") or q/!q to quit: ")
		var input string
		fmt.Scanf("%s", &input)
		if input == "q" || input == "!q" || input == "quit" || input == "exit" {
			return nil, nil // Clean exit
		}
		if num, err := parseNumber(input); err == nil && num >= 1 && num <= len(incResp.Incidents) {
			choice = num
			break
		}
		fmt.Println("Invalid selection, try again.")
	}

	selected := &incResp.Incidents[choice-1]

	// Session ID = userID-incidentID for continuity across sessions
	app.sessionID = fmt.Sprintf("%s-%s", app.userID, selected.ID)

	return selected, nil
}

func (app *App) startShell() error {
	// Check if tmux is available
	tmuxPath, err := exec.LookPath("tmux")
	useTmux := err == nil

	if useTmux {
		// Create unique tmux session name for this incident
		app.tmuxSession = fmt.Sprintf("sreshell-%d", app.incident.IncidentNum)

		// Kill any existing session with this name (cleanup from crashes)
		exec.Command(tmuxPath, "kill-session", "-t", app.tmuxSession).Run()

		// Start tmux with a new session
		// -2 forces 256 colors, uses user's default shell
		app.shellCmd = exec.Command(tmuxPath, "new-session", "-A", "-s", app.tmuxSession)
		app.shellCmd.Env = append(os.Environ(),
			fmt.Sprintf("PAGERDUTY_INCIDENT=%s", app.incident.ID),
			fmt.Sprintf("PAGERDUTY_INCIDENT_NUM=%d", app.incident.IncidentNum),
		)
	} else {
		// Fall back to direct shell if tmux not available
		shell := os.Getenv("SHELL")
		if shell == "" {
			shell = "/bin/bash"
		}
		app.shellCmd = exec.Command(shell)
		app.shellCmd.Env = append(os.Environ(),
			fmt.Sprintf("PAGERDUTY_INCIDENT=%s", app.incident.ID),
			fmt.Sprintf("PAGERDUTY_INCIDENT_NUM=%d", app.incident.IncidentNum),
		)
	}

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
				Cols: uint16(app.width*6/10 - 1),
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
				Cols: uint16(app.width*6/10 - 1),
			})
			// Clear output buffer - resize causes prompt redraw we don't want to capture
			app.mu.Lock()
			app.outputBuffer.Reset()
			app.mu.Unlock()
			app.draw()

		case *tcell.EventMouse:
			mx, my := ev.Position()
			shellWidth := app.width * 6 / 10
			btn := ev.Buttons()

			// Determine which pane mouse is in
			mousePane := "shell"
			if mx >= shellWidth {
				mousePane = "sre"
			}

			// Handle mouse wheel for scrolling
			if btn&tcell.WheelUp != 0 {
				if mousePane == "shell" {
					app.shellScroll += 3
					if app.shellScroll > len(app.shellOutput) {
						app.shellScroll = len(app.shellOutput)
					}
				} else {
					app.sreScroll += 3
					if app.sreScroll > len(app.sreOutput)*2 {
						app.sreScroll = len(app.sreOutput) * 2
					}
				}
				app.draw()
			} else if btn&tcell.WheelDown != 0 {
				if mousePane == "shell" {
					app.shellScroll -= 3
					if app.shellScroll < 0 {
						app.shellScroll = 0
					}
				} else {
					app.sreScroll -= 3
					if app.sreScroll < 0 {
						app.sreScroll = 0
					}
				}
				app.draw()
			} else if btn&tcell.Button1 != 0 {
				// Left button pressed or dragging
				if !app.selecting {
					// Start selection
					app.selecting = true
					app.selPane = mousePane
					app.selStartX = mx
					app.selStartY = my
					app.selEndX = mx
					app.selEndY = my
				} else if app.selPane == mousePane {
					// Continue selection within same pane
					app.selEndX = mx
					app.selEndY = my
				}
				app.draw()
			} else if app.selecting {
				// Button released - copy selection and clear
				app.copySelection()
				app.selecting = false
				app.draw()
			}

		case *tcell.EventKey:
			// Dismiss help on any key if showing
			if app.showHelp {
				app.showHelp = false
				app.draw()
				continue
			}

			// Toggle help with ?
			if ev.Rune() == '?' {
				app.showHelp = true
				app.draw()
				continue
			}

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

			// Page Up/Down for scrolling active pane
			if ev.Key() == tcell.KeyPgUp {
				if app.inputMode == "shell" {
					app.shellScroll += 10
					if app.shellScroll > len(app.shellOutput) {
						app.shellScroll = len(app.shellOutput)
					}
				} else {
					app.sreScroll += 10
					if app.sreScroll > len(app.sreOutput)*2 { // rough estimate with wrapping
						app.sreScroll = len(app.sreOutput) * 2
					}
				}
				app.draw()
				continue
			}
			if ev.Key() == tcell.KeyPgDn {
				if app.inputMode == "shell" {
					app.shellScroll -= 10
					if app.shellScroll < 0 {
						app.shellScroll = 0
					}
				} else {
					app.sreScroll -= 10
					if app.sreScroll < 0 {
						app.sreScroll = 0
					}
				}
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
	case tcell.KeyUp:
		// Scroll up
		app.shellScroll += 1
		if app.shellScroll > len(app.shellOutput) {
			app.shellScroll = len(app.shellOutput)
		}
		app.draw()
		return
	case tcell.KeyDown:
		// Scroll down
		app.shellScroll -= 1
		if app.shellScroll < 0 {
			app.shellScroll = 0
		}
		app.draw()
		return
	case tcell.KeyLeft:
		// If input empty or cursor at start: navigate history (older)
		if app.inputBuffer == "" || app.cursorPos == 0 {
			if len(app.cmdHistory) > 0 {
				if app.historyIdx == len(app.cmdHistory) {
					app.historyTmp = app.inputBuffer
				}
				if app.historyIdx > 0 {
					app.historyIdx--
					app.inputBuffer = app.cmdHistory[app.historyIdx]
					app.cursorPos = len(app.inputBuffer)
				}
			}
		} else {
			// Move cursor left
			app.cursorPos--
		}
		app.draw()
		return
	case tcell.KeyRight:
		// If input empty or cursor at end: navigate history (newer)
		if app.inputBuffer == "" || app.cursorPos == len(app.inputBuffer) {
			if app.historyIdx < len(app.cmdHistory) {
				app.historyIdx++
				if app.historyIdx == len(app.cmdHistory) {
					app.inputBuffer = app.historyTmp
				} else {
					app.inputBuffer = app.cmdHistory[app.historyIdx]
				}
				app.cursorPos = len(app.inputBuffer)
			}
		} else {
			// Move cursor right
			app.cursorPos++
		}
		app.draw()
		return
	case tcell.KeyEnter:
		cmd := strings.TrimSpace(app.inputBuffer)

		// Check for special commands - don't log these
		if cmd == "!q" || cmd == "!quit" || cmd == "!exit" {
			close(app.quit)
			return
		}

		// Skip logging special commands that start with !
		if strings.HasPrefix(cmd, "!") {
			app.inputBuffer = ""
			app.cursorPos = 0
			app.draw()
			return
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

		// Log command for notes
		if cmd != "" {
			app.cmdBuffer.WriteString(cmd + "\n")
		}
		// Send to shell (shell will echo it)
		app.shellPty.WriteString(app.inputBuffer + "\n")
		app.inputBuffer = ""
		app.cursorPos = 0
		app.shellScroll = 0 // Reset scroll to show latest

		// After a delay, capture output for notes
		go func(command string) {
			time.Sleep(500 * time.Millisecond)
			app.mu.Lock()
			output := app.outputBuffer.String()
			app.outputBuffer.Reset()
			app.mu.Unlock()

			// Save note if there was an actual command
			if command != "" {
				// Strip prompt lines from output
				output = stripTrailingPrompt(output)
				output = strings.TrimSpace(output)
				// Format: command + output
				note := fmt.Sprintf("$ %s\n%s", command, output)
				app.queueNote(note)
			}
		}(cmd)

		// If empty enter, just clear buffer (don't let prompt accumulate)
		if cmd == "" {
			go func() {
				time.Sleep(300 * time.Millisecond)
				app.mu.Lock()
				app.outputBuffer.Reset()
				app.mu.Unlock()
			}()
		}

	case tcell.KeyBackspace, tcell.KeyBackspace2:
		if app.cursorPos > 0 {
			app.inputBuffer = app.inputBuffer[:app.cursorPos-1] + app.inputBuffer[app.cursorPos:]
			app.cursorPos--
		}
	case tcell.KeyDelete:
		if app.cursorPos < len(app.inputBuffer) {
			app.inputBuffer = app.inputBuffer[:app.cursorPos] + app.inputBuffer[app.cursorPos+1:]
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
	case tcell.KeyUp:
		// Scroll up
		app.sreScroll += 1
		if app.sreScroll > len(app.sreOutput)*2 {
			app.sreScroll = len(app.sreOutput) * 2
		}
		app.draw()
		return
	case tcell.KeyDown:
		// Scroll down
		app.sreScroll -= 1
		if app.sreScroll < 0 {
			app.sreScroll = 0
		}
		app.draw()
		return
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

		// Refresh analysis with fresh context from MCP
		if query == "!r" || query == "!refresh" {
			app.inputBuffer = ""
			app.cursorPos = 0
			app.addSREOutput("Syncing notes...")
			app.draw()
			go func() {
				app.flushNotes() // Push notes first
				time.Sleep(2 * time.Second) // Wait for PagerDuty to index
				app.refreshSREAnalysis()
			}()
			return
		}

		// Show past incidents
		if query == "!h" || query == "!history" {
			app.inputBuffer = ""
			app.cursorPos = 0
			app.addSREOutput("")
			app.addSREOutput("PAST INCIDENTS:")
			app.mu.Lock()
			cache := app.pastIncidentsCache
			app.mu.Unlock()
			if cache != "" {
				app.addSREOutput(formatIncidents(cache))
			} else {
				app.addSREOutput("  (none cached)")
			}
			app.draw()
			return
		}

		// Show full analysis
		if query == "!a" || query == "!analysis" {
			app.inputBuffer = ""
			app.cursorPos = 0
			app.mu.Lock()
			cache := app.fullAnalysisCache
			app.mu.Unlock()
			if cache != "" {
				app.addSREOutput("")
				app.addSREOutput("FULL ANALYSIS:")
				app.addSREOutput(cache)
			} else {
				app.addSREOutput("  (no analysis cached yet)")
			}
			app.draw()
			return
		}

		if query != "" {
			app.addSREOutput(fmt.Sprintf("> %s", query))
			app.addSREOutput("Syncing notes...")
			app.inputBuffer = ""
			app.cursorPos = 0
			app.draw()

			go func(q string) {
				// Flush notes first so SRE agent has latest context
				app.flushNotes()
				// Wait for PagerDuty to index notes before querying
				time.Sleep(2 * time.Second)

				app.mu.Lock()
				if len(app.sreOutput) > 0 {
					app.sreOutput[len(app.sreOutput)-1] = "Thinking..."
				}
				app.mu.Unlock()
				app.draw()

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
		app.addSREOutput("Syncing notes...")
		app.draw()
		go func() {
			app.flushNotes() // Push notes first
			time.Sleep(2 * time.Second) // Wait for PagerDuty to index
			app.mu.Lock()
			if len(app.sreOutput) > 0 {
				app.sreOutput[len(app.sreOutput)-1] = "Thinking..."
			}
			app.mu.Unlock()
			app.draw()

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
	midX := w * 6 / 10 // 60% for shell, 40% for SRE

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

	// Draw shell output (left pane) with scroll support
	shellHeight := h - 4
	totalShellLines := len(app.shellOutput)
	startLine := 0
	if totalShellLines > shellHeight {
		startLine = totalShellLines - shellHeight - app.shellScroll
		if startLine < 0 {
			startLine = 0
		}
	}
	endLine := startLine + shellHeight
	if endLine > totalShellLines {
		endLine = totalShellLines
	}
	for i, line := range app.shellOutput[startLine:endLine] {
		y := 2 + i
		if y >= h-2 {
			break
		}
		cleaned := stripANSI(line)
		if len(cleaned) > midX-1 {
			cleaned = cleaned[:midX-1]
		}
		app.drawStringWithSelection(0, y, cleaned, style, "shell")
	}
	// Show scroll indicator for shell
	if app.shellScroll > 0 {
		app.drawString(midX-6, 0, fmt.Sprintf("[+%d]", app.shellScroll), statusStyle)
	}

	// Draw SRE output (right pane) with scroll and markdown
	sreHeight := h - 4
	// Flatten wrapped lines first
	maxWidth := w - midX - 3
	var sreLines []string
	for _, line := range app.sreOutput {
		wrapped := wrapText(line, maxWidth)
		sreLines = append(sreLines, wrapped...)
	}
	totalSRELines := len(sreLines)
	startSRE := 0
	if totalSRELines > sreHeight {
		startSRE = totalSRELines - sreHeight - app.sreScroll
		if startSRE < 0 {
			startSRE = 0
		}
	}
	endSRE := startSRE + sreHeight
	if endSRE > totalSRELines {
		endSRE = totalSRELines
	}
	for i, line := range sreLines[startSRE:endSRE] {
		y := 2 + i
		if y >= h-2 {
			break
		}
		app.drawMarkdownLineWithSelection(midX+2, y, line, maxWidth)
	}
	// Show scroll indicator for SRE
	if app.sreScroll > 0 {
		app.drawString(w-8, 0, fmt.Sprintf("[+%d]", app.sreScroll), statusStyle)
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

	// Status message (shown for 5 seconds) or help text
	var rightText string
	rightStyle := tcell.StyleDefault.Foreground(tcell.ColorDarkGray)
	if app.statusMsg != "" && time.Since(app.statusMsgTime) < 5*time.Second {
		rightText = app.statusMsg
		rightStyle = tcell.StyleDefault.Foreground(tcell.ColorGreen)
	} else {
		// Clear old status
		if app.statusMsg != "" {
			app.statusMsg = ""
		}
		// Show help hints
		if app.inputMode == "shell" {
			rightText = "[?:help] [!q:quit]"
		} else {
			rightText = "[!n:next] [!r:refresh] [!q:quit]"
		}
	}
	app.drawString(w-len(rightText)-1, inputY, rightText, rightStyle)

	// Draw help popup if showing
	if app.showHelp {
		app.drawHelpPopup()
	}

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

func (app *App) drawStringWithSelection(x, y int, s string, style tcell.Style, pane string) {
	selStyle := tcell.StyleDefault.Background(tcell.ColorBlue).Foreground(tcell.ColorWhite)
	for i, r := range s {
		px := x + i
		if px >= app.width {
			break
		}
		charStyle := style
		if app.selecting && app.selPane == pane && app.isInSelection(px, y) {
			charStyle = selStyle
		}
		app.screen.SetContent(px, y, r, nil, charStyle)
	}
}

func (app *App) isInSelection(x, y int) bool {
	// Normalize selection coordinates (start <= end)
	startY, endY := app.selStartY, app.selEndY
	startX, endX := app.selStartX, app.selEndX
	if startY > endY || (startY == endY && startX > endX) {
		startY, endY = endY, startY
		startX, endX = endX, startX
	}

	if y < startY || y > endY {
		return false
	}
	if y == startY && y == endY {
		return x >= startX && x <= endX
	}
	if y == startY {
		return x >= startX
	}
	if y == endY {
		return x <= endX
	}
	return true
}

func (app *App) copySelection() {
	if !app.selecting {
		return
	}

	// Get selection bounds
	startY, endY := app.selStartY, app.selEndY
	startX, endX := app.selStartX, app.selEndX
	if startY > endY || (startY == endY && startX > endX) {
		startY, endY = endY, startY
		startX, endX = endX, startX
	}

	shellWidth := app.width * 6 / 10
	var lines []string

	if app.selPane == "shell" {
		// Get visible shell lines
		shellHeight := app.height - 4
		totalLines := len(app.shellOutput)
		viewStart := 0
		if totalLines > shellHeight {
			viewStart = totalLines - shellHeight - app.shellScroll
			if viewStart < 0 {
				viewStart = 0
			}
		}

		for screenY := startY; screenY <= endY; screenY++ {
			lineIdx := viewStart + (screenY - 2)
			if lineIdx < 0 || lineIdx >= len(app.shellOutput) {
				continue
			}
			line := stripANSI(app.shellOutput[lineIdx])
			if len(line) > shellWidth-1 {
				line = line[:shellWidth-1]
			}

			// Extract selected portion
			lineStartX := 0
			lineEndX := len(line)
			if screenY == startY {
				lineStartX = startX
			}
			if screenY == endY {
				lineEndX = endX + 1
			}
			if lineStartX < 0 {
				lineStartX = 0
			}
			if lineEndX > len(line) {
				lineEndX = len(line)
			}
			if lineStartX < lineEndX {
				lines = append(lines, line[lineStartX:lineEndX])
			}
		}
	} else {
		// Get visible SRE lines (account for wrapping)
		maxWidth := app.width - shellWidth - 3
		var sreLines []string
		for _, line := range app.sreOutput {
			wrapped := wrapText(line, maxWidth)
			sreLines = append(sreLines, wrapped...)
		}

		sreHeight := app.height - 4
		totalLines := len(sreLines)
		viewStart := 0
		if totalLines > sreHeight {
			viewStart = totalLines - sreHeight - app.sreScroll
			if viewStart < 0 {
				viewStart = 0
			}
		}

		for screenY := startY; screenY <= endY; screenY++ {
			lineIdx := viewStart + (screenY - 2)
			if lineIdx < 0 || lineIdx >= len(sreLines) {
				continue
			}
			line := sreLines[lineIdx]

			// Adjust X coordinates for SRE pane offset
			adjStartX := startX - (shellWidth + 2)
			adjEndX := endX - (shellWidth + 2)

			lineStartX := 0
			lineEndX := len(line)
			if screenY == startY {
				lineStartX = adjStartX
			}
			if screenY == endY {
				lineEndX = adjEndX + 1
			}
			if lineStartX < 0 {
				lineStartX = 0
			}
			if lineEndX > len(line) {
				lineEndX = len(line)
			}
			if lineStartX < lineEndX {
				lines = append(lines, line[lineStartX:lineEndX])
			}
		}
	}

	if len(lines) == 0 {
		return
	}

	text := strings.Join(lines, "\n")
	app.copyToClipboard(text)
}

func (app *App) copyToClipboard(text string) {
	// Try pbcopy (macOS) first, then xclip (Linux)
	var cmd *exec.Cmd
	if _, err := exec.LookPath("pbcopy"); err == nil {
		cmd = exec.Command("pbcopy")
	} else if _, err := exec.LookPath("xclip"); err == nil {
		cmd = exec.Command("xclip", "-selection", "clipboard")
	} else if _, err := exec.LookPath("xsel"); err == nil {
		cmd = exec.Command("xsel", "--clipboard", "--input")
	} else {
		return // No clipboard command available
	}

	cmd.Stdin = strings.NewReader(text)
	cmd.Run()
}

func (app *App) drawHelpPopup() {
	help := []string{
		" HELP (press any key to close) ",
		"",
		" Tab        Switch pane",
		" Up/Dn      Scroll",
		" Left/Right History (shell)",
		"",
		" SRE:  !n next steps",
		"       !r refresh analysis",
		"",
		" !q   Quit to incident list",
	}

	popupW := 42
	popupH := len(help) + 2
	startX := (app.width - popupW) / 2
	startY := (app.height - popupH) / 2

	boxStyle := tcell.StyleDefault.Background(tcell.ColorBlack).Foreground(tcell.ColorWhite)
	headerStyle := tcell.StyleDefault.Background(tcell.ColorTeal).Foreground(tcell.ColorBlack).Bold(true)

	// Draw box
	for y := 0; y < popupH; y++ {
		for x := 0; x < popupW; x++ {
			app.screen.SetContent(startX+x, startY+y, ' ', nil, boxStyle)
		}
	}

	// Draw content
	for i, line := range help {
		style := boxStyle
		if i == 0 {
			style = headerStyle
		}
		for j, r := range line {
			if startX+j+1 < app.width {
				app.screen.SetContent(startX+j+1, startY+i+1, r, nil, style)
			}
		}
	}
}

func (app *App) drawMarkdownLine(x, y int, s string, maxWidth int) {
	boldStyle := tcell.StyleDefault.Bold(true).Foreground(tcell.ColorYellow)
	headerStyle := tcell.StyleDefault.Bold(true).Foreground(tcell.ColorTeal)
	codeStyle := tcell.StyleDefault.Foreground(tcell.ColorGreen)
	normalStyle := tcell.StyleDefault

	col := x
	i := 0
	runes := []rune(s)

	trimmed := strings.TrimSpace(s)

	// Skip code fence markers (``` or `)
	if trimmed == "```" || trimmed == "`" || strings.HasPrefix(trimmed, "```") {
		return
	}

	// Check if line looks like a shell command - render in code style
	cmdPrefixes := []string{
		"kubectl ", "docker ", "curl ", "systemctl ", "git ", "npm ", "pip ",
		"aws ", "gcloud ", "helm ", "terraform ", "ansible ", "ssh ", "scp ",
		"cat ", "grep ", "tail ", "head ", "less ", "vi ", "vim ", "nano ",
		"ls ", "cd ", "pwd ", "mkdir ", "rm ", "cp ", "mv ", "chmod ",
		"ps ", "top ", "htop ", "kill ", "pkill ", "journalctl ", "dmesg ",
		"ping ", "netstat ", "ss ", "nc ", "telnet ", "dig ", "nslookup ",
		"mysql ", "psql ", "redis-cli ", "mongo ", "sqlite3 ", "$ ",
	}
	isCommand := false
	for _, prefix := range cmdPrefixes {
		if strings.HasPrefix(trimmed, prefix) {
			isCommand = true
			break
		}
	}
	if isCommand {
		displayText := trimmed
		if strings.HasPrefix(trimmed, "$ ") {
			displayText = trimmed[2:]
		}
		for _, r := range []rune(displayText) {
			if col >= x+maxWidth || col >= app.width {
				break
			}
			app.screen.SetContent(col, y, r, nil, codeStyle)
			col++
		}
		return
	}

	// Check for header prefix (markdown #, ##, ###, ####, ##### or blockquote >)
	isHeader := strings.HasPrefix(trimmed, "##### ") ||
		strings.HasPrefix(trimmed, "#### ") ||
		strings.HasPrefix(trimmed, "### ") ||
		strings.HasPrefix(trimmed, "## ") ||
		strings.HasPrefix(trimmed, "# ") ||
		strings.HasPrefix(trimmed, ">> ") ||
		strings.HasPrefix(trimmed, "> ")
	if isHeader {
		// Strip the prefix markers and draw bold/colored
		displayText := trimmed
		if strings.HasPrefix(trimmed, "##### ") {
			displayText = trimmed[6:]
		} else if strings.HasPrefix(trimmed, "#### ") {
			displayText = trimmed[5:]
		} else if strings.HasPrefix(trimmed, "### ") {
			displayText = trimmed[4:]
		} else if strings.HasPrefix(trimmed, "## ") {
			displayText = trimmed[3:]
		} else if strings.HasPrefix(trimmed, "# ") {
			displayText = trimmed[2:]
		} else if strings.HasPrefix(trimmed, ">> ") {
			displayText = trimmed[3:]
		} else if strings.HasPrefix(trimmed, "> ") {
			displayText = trimmed[2:]
		}
		// Draw header text
		for _, r := range []rune(displayText) {
			if col >= x+maxWidth || col >= app.width {
				break
			}
			app.screen.SetContent(col, y, r, nil, headerStyle)
			col++
		}
		return
	}

	for i < len(runes) {
		if col >= x+maxWidth || col >= app.width {
			break
		}

		// Check for bold **text**
		if i+1 < len(runes) && runes[i] == '*' && runes[i+1] == '*' {
			// Find closing **
			end := -1
			for j := i + 2; j < len(runes)-1; j++ {
				if runes[j] == '*' && runes[j+1] == '*' {
					end = j
					break
				}
			}
			if end > 0 {
				// Skip opening **
				i += 2
				// Draw bold text
				for i < end && col < x+maxWidth && col < app.width {
					app.screen.SetContent(col, y, runes[i], nil, boldStyle)
					col++
					i++
				}
				// Skip closing **
				i += 2
				continue
			}
		}

		// Check for inline code `text`
		if runes[i] == '`' {
			end := -1
			for j := i + 1; j < len(runes); j++ {
				if runes[j] == '`' {
					end = j
					break
				}
			}
			if end > 0 {
				i++ // Skip opening `
				for i < end && col < x+maxWidth && col < app.width {
					app.screen.SetContent(col, y, runes[i], nil, codeStyle)
					col++
					i++
				}
				i++ // Skip closing `
				continue
			}
		}

		// Normal character
		app.screen.SetContent(col, y, runes[i], nil, normalStyle)
		col++
		i++
	}
}

func (app *App) drawMarkdownLineWithSelection(x, y int, s string, maxWidth int) {
	// First draw the markdown-styled line
	app.drawMarkdownLine(x, y, s, maxWidth)

	// Then overlay selection highlighting if selecting in SRE pane
	if app.selecting && app.selPane == "sre" {
		selStyle := tcell.StyleDefault.Background(tcell.ColorBlue).Foreground(tcell.ColorWhite)
		for col := x; col < x+maxWidth && col < app.width; col++ {
			if app.isInSelection(col, y) {
				// Get current content and apply selection style
				mainc, combc, _, _ := app.screen.GetContent(col, y)
				app.screen.SetContent(col, y, mainc, combc, selStyle)
			}
		}
	}
}

func (app *App) addShellOutput(text string) {
	app.mu.Lock()
	defer app.mu.Unlock()

	clean := stripANSI(text)
	lines := strings.Split(clean, "\n")
	app.shellOutput = append(app.shellOutput, lines...)

	// Keep buffer manageable
	if len(app.shellOutput) > 1000 {
		app.shellOutput = app.shellOutput[len(app.shellOutput)-500:]
	}
}

func (app *App) addSREOutput(text string) {
	app.mu.Lock()
	defer app.mu.Unlock()

	// Strip ANSI but keep UTF-8/markdown for rendering
	clean := stripANSI(text)
	lines := strings.Split(clean, "\n")

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Add blank line before headers
		if strings.HasPrefix(trimmed, "#") ||
			strings.HasPrefix(trimmed, "TRIAGE:") ||
			strings.HasPrefix(trimmed, "POTENTIAL ROOT CAUSE") ||
			strings.HasPrefix(trimmed, "NEXT STEPS") ||
			strings.HasPrefix(trimmed, "RECENT ") ||
			strings.HasPrefix(trimmed, "RELATED ") {
			if len(app.sreOutput) > 0 && app.sreOutput[len(app.sreOutput)-1] != "" {
				app.sreOutput = append(app.sreOutput, "")
			}
		}
		app.sreOutput = append(app.sreOutput, line)
	}

	// Keep buffer manageable
	if len(app.sreOutput) > 500 {
		app.sreOutput = app.sreOutput[len(app.sreOutput)-250:]
	}

	// Debug: append to file in current dir
	if f, err := os.OpenFile("sre_output.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
		f.WriteString(text + "\n")
		f.Close()
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
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
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

func (app *App) refreshSREAnalysis() {
	app.addSREOutput("")
	app.addSREOutput("=== Refreshing Analysis ===")
	app.addSREOutput("Fetching latest incident data...")
	app.draw()

	// Fetch fresh context from standard MCP
	details, err := app.callStandardMCP("get_incident", map[string]interface{}{
		"id": app.incident.ID,
	})
	if err != nil {
		app.addSREOutput(fmt.Sprintf("  [incident error: %v]", err))
	} else {
		app.addSREOutput(fmt.Sprintf("  Got incident details (%d chars)", len(details)))
	}
	app.draw()

	// Get incident notes (timeline)
	notes, err := app.callStandardMCP("list_incident_notes", map[string]interface{}{
		"id": app.incident.ID,
	})
	if err != nil {
		app.addSREOutput(fmt.Sprintf("  [notes error: %v]", err))
	} else {
		app.addSREOutput(fmt.Sprintf("  Got incident notes (%d chars)", len(notes)))
	}
	app.draw()

	// Build context for SRE agent
	var context strings.Builder
	context.WriteString(fmt.Sprintf("Analyze incident %s with the latest updates.\n\n", app.incident.ID))
	if details != "" {
		context.WriteString("Current Incident Details:\n")
		context.WriteString(details)
		context.WriteString("\n\n")
	}
	if notes != "" {
		context.WriteString("Incident Timeline/Notes:\n")
		context.WriteString(notes)
		context.WriteString("\n\n")
	}
	context.WriteString("Based on the latest notes and timeline, what is the current status, root cause analysis, and recommended next steps?")

	app.addSREOutput("")
	app.addSREOutput("Running SRE analysis...")
	app.draw()

	// Show progress while waiting
	done := make(chan bool)
	go func() {
		dots := 0
		for {
			select {
			case <-done:
				return
			case <-time.After(1 * time.Second):
				dots++
				app.mu.Lock()
				if len(app.sreOutput) > 0 {
					app.sreOutput[len(app.sreOutput)-1] = fmt.Sprintf("Running SRE analysis%s (%ds)", strings.Repeat(".", dots%4), dots)
				}
				app.mu.Unlock()
				app.draw()
			}
		}
	}()

	resp, err := app.querySREAgent(context.String())
	close(done)

	// Clear progress line
	app.mu.Lock()
	if len(app.sreOutput) > 0 {
		app.sreOutput = app.sreOutput[:len(app.sreOutput)-1]
	}
	app.mu.Unlock()

	if err != nil {
		app.addSREOutput(fmt.Sprintf("Error: %v", err))
	} else if resp == "" {
		app.addSREOutput("(SRE agent returned empty response)")
	} else {
		app.addSREOutput("")
		app.addSREOutput("=== Updated Analysis ===")
		app.addSREOutput("")
		app.addSREOutput(resp)
	}
	app.draw()
}

func (app *App) querySREAgent(query string) (string, error) {
	mcpResponse, err := app.callAdvanceMCP(query)
	if err != nil {
		return "", err
	}
	return app.formatMCPResponse(mcpResponse, query), nil
}

func (app *App) callStandardMCP(toolName string, arguments map[string]interface{}) (string, error) {
	// Standard PagerDuty MCP endpoint
	mcpURL := "https://mcp.pagerduty.com/mcp"

	reqBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      app.userID,
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name":      toolName,
			"arguments": arguments,
		},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", mcpURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Token token="+app.apiToken)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		// Clean error message - strip HTML
		errMsg := string(respBody)
		if strings.Contains(errMsg, "<html>") {
			errMsg = fmt.Sprintf("Server error %d", resp.StatusCode)
		}
		return "", fmt.Errorf("%s", errMsg)
	}

	var mcpResp MCPResponse
	if err := json.Unmarshal(respBody, &mcpResp); err != nil {
		return "", err
	}

	if mcpResp.Error != nil {
		return "", fmt.Errorf("MCP error: %s", mcpResp.Error.Message)
	}

	// Extract text content
	var result strings.Builder
	for _, content := range mcpResp.Result.Content {
		if content.Type == "text" {
			result.WriteString(content.Text)
			result.WriteString("\n")
		}
	}

	return result.String(), nil
}

func (app *App) callAdvanceMCP(message string) (string, error) {
	// PagerDuty Advance MCP endpoint (trailing slash required)
	mcpURL := "https://mcp.pagerduty.com/pagerduty-advance-mcp/"

	// session_id is required for SRE agent, id might need to be user ID
	reqBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      app.userID,
		"method":  "tools/call",
		"params": map[string]interface{}{
			"name": "sre_agent_tool",
			"arguments": map[string]interface{}{
				"incident_id": app.incident.ID,
				"message":     message,
				"session_id":  app.sessionID,
			},
		},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	client := &http.Client{Timeout: 60 * time.Second}

	// Retry logic for transient errors (EOF, connection reset, 5xx)
	var resp *http.Response
	var respBody []byte
	var req *http.Request
	maxRetries := 3
	for attempt := 0; attempt < maxRetries; attempt++ {
		req, err = http.NewRequest("POST", mcpURL, bytes.NewReader(body))
		if err != nil {
			return "", err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Token token="+app.apiToken)

		resp, err = client.Do(req)
		if err != nil {
			// Retry on network errors (EOF, connection reset, etc.)
			if attempt < maxRetries-1 {
				time.Sleep(time.Duration(attempt+1) * time.Second)
				continue
			}
			return "", err
		}

		respBody, _ = io.ReadAll(resp.Body)
		resp.Body.Close()

		// Retry on server errors (502, 503, 504)
		if resp.StatusCode >= 500 && resp.StatusCode < 600 {
			if attempt < maxRetries-1 {
				time.Sleep(time.Duration(attempt+1) * time.Second)
				continue
			}
		}
		break
	}

	if resp.StatusCode != 200 {
		// Clean error message - strip HTML
		errMsg := string(respBody)
		if strings.Contains(errMsg, "<html>") {
			errMsg = fmt.Sprintf("Server error %d (try again)", resp.StatusCode)
		}
		return "", fmt.Errorf("%s", errMsg)
	}

	// Parse response
	var mcpResp MCPResponse
	if err := json.Unmarshal(respBody, &mcpResp); err != nil {
		return "", err
	}

	if mcpResp.Error != nil {
		return "", fmt.Errorf("MCP error: %s", mcpResp.Error.Message)
	}

	// Extract text content from response
	var result strings.Builder
	for _, content := range mcpResp.Result.Content {
		if content.Type == "text" {
			// The text field contains JSON with a "message" field
			var textContent struct {
				Message string `json:"message"`
			}
			if err := json.Unmarshal([]byte(content.Text), &textContent); err == nil && textContent.Message != "" {
				result.WriteString(textContent.Message)
			} else {
				result.WriteString(content.Text)
			}
			result.WriteString("\n")
		}
	}

	return result.String(), nil
}

func (app *App) formatMCPResponse(response string, query string) string {
	// Just return the response as-is
	return response
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

	// Copy queue and clear
	notes := make([]string, len(app.noteQueue))
	copy(notes, app.noteQueue)
	count := len(notes)
	app.noteQueue = nil
	app.noteMu.Unlock()

	// Post each note separately (one note = one command + response)
	fromEmail := os.Getenv("PAGERDUTY_EMAIL")
	if fromEmail == "" {
		fromEmail = "sreshell@local"
	}
	url := fmt.Sprintf("%s/incidents/%s/notes", app.baseURL, app.incident.ID)

	for _, note := range notes {
		// Truncate if too long
		if len(note) > 25000 {
			note = note[:25000] + "\n[truncated]"
		}

		noteReq := NoteRequest{}
		noteReq.Note.Content = note

		body, _ := json.Marshal(noteReq)
		req, err := http.NewRequest("POST", url, bytes.NewReader(body))
		if err != nil {
			continue
		}
		req.Header.Set("Authorization", "Token token="+app.apiToken)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("From", fromEmail)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode != 201 {
			// Note failed, but continue with others
			continue
		}
	}

	app.setStatus(fmt.Sprintf("Saved %d notes (!r to refresh)", count))
}

func (app *App) setStatus(msg string) {
	app.mu.Lock()
	app.statusMsg = msg
	app.statusMsgTime = time.Now()
	app.mu.Unlock()
	app.draw()
}

// Helper functions

func isPromptLine(line string) bool {
	line = strings.TrimSpace(line)
	if line == "" {
		return true
	}
	// Only match clear prompt endings
	if strings.HasSuffix(line, "❯") ||
		strings.HasSuffix(line, " $") ||
		strings.HasSuffix(line, " #") ||
		strings.HasSuffix(line, " %") ||
		strings.Contains(line, "➜") {
		return true
	}
	return false
}

func stripTrailingPrompt(s string) string {
	lines := strings.Split(s, "\n")

	// Remove trailing prompt lines
	for len(lines) > 0 && isPromptLine(lines[len(lines)-1]) {
		lines = lines[:len(lines)-1]
	}

	// Remove leading prompt lines (echo of prompt before command)
	for len(lines) > 0 && isPromptLine(lines[0]) {
		lines = lines[1:]
	}

	return strings.Join(lines, "\n")
}

func stripMarkdown(s string) string {
	// Remove bold **text** and __text__
	s = strings.ReplaceAll(s, "**", "")
	s = strings.ReplaceAll(s, "__", "")
	// Remove italic *text* (but not bullet points)
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		// Only strip * if not a bullet point (line starting with * or -)
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "*") && !strings.HasPrefix(trimmed, "-") {
			// Replace paired *text* with text
			for strings.Contains(line, "*") {
				start := strings.Index(line, "*")
				end := strings.Index(line[start+1:], "*")
				if end > 0 {
					line = line[:start] + line[start+1:start+1+end] + line[start+1+end+1:]
				} else {
					break
				}
			}
			lines[i] = line
		}
	}
	s = strings.Join(lines, "\n")
	// Remove code blocks ```
	s = strings.ReplaceAll(s, "```bash", "")
	s = strings.ReplaceAll(s, "```", "")
	// Remove inline code `text`
	s = strings.ReplaceAll(s, "`", "")
	// Simplify headers
	s = strings.ReplaceAll(s, "#### ", ">> ")
	s = strings.ReplaceAll(s, "### ", ">> ")
	s = strings.ReplaceAll(s, "## ", "> ")
	s = strings.ReplaceAll(s, "# ", "> ")
	// Remove link formatting [text](url) -> text (url)
	for strings.Contains(s, "](") {
		start := strings.Index(s, "[")
		mid := strings.Index(s, "](")
		end := strings.Index(s[mid:], ")")
		if start >= 0 && mid > start && end > 0 {
			text := s[start+1 : mid]
			url := s[mid+2 : mid+end]
			s = s[:start] + text + " (" + url + ")" + s[mid+end+1:]
		} else {
			break
		}
	}
	return s
}

func formatIncidentDetails(raw string) string {
	// Try direct object first (MCP returns it unwrapped)
	var inc struct {
		IncidentNumber int    `json:"incident_number"`
		Title          string `json:"title"`
		Summary        string `json:"summary"`
		Status         string `json:"status"`
		Urgency        string `json:"urgency"`
		CreatedAt      string `json:"created_at"`
		Service        struct {
			Summary string `json:"summary"`
		} `json:"service"`
	}

	if err := json.Unmarshal([]byte(raw), &inc); err == nil && inc.Title != "" {
		var result strings.Builder

		ts := inc.CreatedAt
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			ts = t.Format("Jan 2 15:04")
		}

		svc := inc.Service.Summary
		if svc == "" {
			svc = "unknown"
		}

		result.WriteString(fmt.Sprintf("#%d | %s | %s\n", inc.IncidentNumber, inc.Status, inc.Urgency))
		result.WriteString(fmt.Sprintf("Service: %s\n", svc))
		result.WriteString(fmt.Sprintf("Started: %s\n", ts))
		result.WriteString(fmt.Sprintf("%s\n", inc.Title))

		return result.String()
	}

	if len(raw) > 300 {
		return raw[:300] + "..."
	}
	return raw
}

func formatChanges(raw string) string {
	// MCP returns {"response":[...]} structure
	var resp struct {
		Response []struct {
			Summary   string `json:"summary"`
			Timestamp string `json:"timestamp"`
			Links     []struct {
				Href string `json:"href"`
			} `json:"links"`
		} `json:"response"`
	}

	if err := json.Unmarshal([]byte(raw), &resp); err == nil && len(resp.Response) > 0 {
		var result strings.Builder
		for _, c := range resp.Response {
			ts := c.Timestamp
			if t, err := time.Parse(time.RFC3339, ts); err == nil {
				ts = t.Format("Jan 2 15:04")
			}
			// Compact: "- summary (ts)"
			summary := c.Summary
			if len(summary) > 50 {
				summary = summary[:47] + "..."
			}
			result.WriteString(fmt.Sprintf("- %s (%s)\n", summary, ts))
		}
		return result.String()
	}

	// Fallback
	if len(raw) > 300 {
		return raw[:300] + "..."
	}
	return raw
}

func formatIncidentsCompact(raw string) string {
	type Inc struct {
		IncidentNumber int    `json:"incident_number"`
		Title          string `json:"title"`
		CreatedAt      string `json:"created_at"`
		HTMLURL        string `json:"html_url"`
	}

	formatList := func(incs []Inc) string {
		var result strings.Builder
		for _, inc := range incs {
			ts := inc.CreatedAt
			if t, err := time.Parse(time.RFC3339, ts); err == nil {
				ts = t.Format("Jan 2")
			}
			title := inc.Title
			if len(title) > 45 {
				title = title[:42] + "..."
			}
			// Compact: "- #num title (date)"
			result.WriteString(fmt.Sprintf("- #%d %s (%s)\n", inc.IncidentNumber, title, ts))
		}
		return result.String()
	}

	// Try {"incidents":[...]}
	var incidents struct {
		Incidents []Inc `json:"incidents"`
	}
	if err := json.Unmarshal([]byte(raw), &incidents); err == nil && len(incidents.Incidents) > 0 {
		return formatList(incidents.Incidents)
	}

	// Try {"response":[...]}
	var resp struct {
		Response []Inc `json:"response"`
	}
	if err := json.Unmarshal([]byte(raw), &resp); err == nil && len(resp.Response) > 0 {
		return formatList(resp.Response)
	}

	return ""
}

func formatIncidents(raw string) string {
	type Inc struct {
		IncidentNumber int    `json:"incident_number"`
		Title          string `json:"title"`
		CreatedAt      string `json:"created_at"`
	}

	formatList := func(incs []Inc) string {
		var result strings.Builder
		for _, inc := range incs {
			ts := inc.CreatedAt
			if t, err := time.Parse(time.RFC3339, ts); err == nil {
				ts = t.Format("Jan 2")
			}
			title := inc.Title
			if len(title) > 45 {
				title = title[:42] + "..."
			}
			result.WriteString(fmt.Sprintf("#%-5d %s | %s\n", inc.IncidentNumber, ts, title))
		}
		return result.String()
	}

	// Try {"incidents":[...]}
	var incidents struct {
		Incidents []Inc `json:"incidents"`
	}
	if err := json.Unmarshal([]byte(raw), &incidents); err == nil && len(incidents.Incidents) > 0 {
		return formatList(incidents.Incidents)
	}

	// Try {"response":[...]}
	var resp struct {
		Response []Inc `json:"response"`
	}
	if err := json.Unmarshal([]byte(raw), &resp); err == nil && len(resp.Response) > 0 {
		return formatList(resp.Response)
	}

	if len(raw) > 300 {
		return raw[:300] + "..."
	}
	return raw
}

func prettyJSON(raw string) string {
	// Try to parse and re-marshal with indentation
	var data interface{}
	if err := json.Unmarshal([]byte(raw), &data); err == nil {
		if pretty, err := json.MarshalIndent(data, "", "  "); err == nil {
			s := string(pretty)
			// Truncate if too long
			if len(s) > 2000 {
				return s[:2000] + "\n..."
			}
			return s
		}
	}
	// Not JSON, return as-is but truncated
	if len(raw) > 1000 {
		return raw[:1000] + "..."
	}
	return raw
}

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
