# SREShell

A split-pane troubleshooting shell that connects to PagerDuty incidents. Run commands on the left, get AI-powered SRE analysis on the right.

**Repository**: https://github.com/justynroberts/sreshell

## Quick Start (5 minutes)

### Step 1: Download SREShell

```bash
# macOS (Apple Silicon)
curl -L https://github.com/justynroberts/sreshell/releases/latest/download/sreshell-darwin-arm64 -o sreshell
chmod +x sreshell

# macOS (Intel)
curl -L https://github.com/justynroberts/sreshell/releases/latest/download/sreshell-darwin-amd64 -o sreshell
chmod +x sreshell

# Linux (x86_64)
curl -L https://github.com/justynroberts/sreshell/releases/latest/download/sreshell-linux-amd64 -o sreshell
chmod +x sreshell
```

### Step 2: Get PagerDuty Token

You only need **one** token. User Token is recommended.

1. Log into PagerDuty
2. Go to **My Profile** → **User Settings** → **Create API User Token**
3. Copy the token (starts with `u+...`)

### Step 3: Configure Shell

```bash
# Add to ~/.zshrc (or ~/.bashrc)
echo 'export PAGERDUTY_USER_TOKEN="YOUR_TOKEN_HERE"' >> ~/.zshrc
source ~/.zshrc
```

### Step 4: Install to PATH

```bash
# Move to a directory in your PATH
sudo mv sreshell /usr/local/bin/

# Or user-only install
mkdir -p ~/bin && mv sreshell ~/bin/
echo 'export PATH="$HOME/bin:$PATH"' >> ~/.zshrc && source ~/.zshrc
```

### Step 5: Run

```bash
sreshell
```

Select an incident and start troubleshooting.

---

## Features

- **Split-pane TUI**: Shell on left (60%), SRE agent on right (40%)
- **PagerDuty Integration**: Select from open incidents, auto-sync notes
- **SRE Triage**: Automatic root cause analysis and numbered next steps
- **Command History**: Left/Right arrows navigate history
- **Note Sync**: Shell commands automatically saved to incident notes

## Prerequisites

- Go 1.21+ (for building from source)
- PagerDuty account with API access
- PagerDuty Advance license (for SRE AI features)

## Dependencies

| Package | Purpose |
|---------|---------|
| `github.com/gdamore/tcell/v2` | Terminal UI framework |
| `github.com/creack/pty` | PTY handling for shell |

## Installation

### From Source

```bash
# Clone repository
git clone <repo>
cd sreshell

# Install dependencies
go mod tidy

# Build
go build -o sreshell main.go

# Install to PATH (choose one)
sudo cp sreshell /usr/local/bin/
# or
cp sreshell ~/bin/  # if ~/bin is in PATH
# or
cp sreshell /opt/homebrew/bin/  # macOS with Homebrew
```

### Verify Installation

```bash
which sreshell
sreshell --help  # Currently just runs - no help flag yet
```

## Configuration

### Required Environment Variables

```bash
# Add to ~/.bashrc, ~/.zshrc, or ~/.profile

# PagerDuty API Token (User Token recommended for full access)
export PAGERDUTY_USER_TOKEN="your-token-here"

# OR use a general API token
export PAGERDUTY_TOKEN="your-token-here"
```

### Optional Environment Variables

```bash
# For EU region
export PAGERDUTY_REGION="eu"

# Email for note attribution (if using service account token)
export PAGERDUTY_EMAIL="your-email@company.com"
```

### Getting a PagerDuty Token

1. Go to PagerDuty → My Profile → User Settings
2. Create a User API Token
3. Copy and add to your shell config

## Usage

```bash
# Start sreshell
sreshell

# Select an incident from the list
[1] TRIG #1234 Kubernetes OOM killer...
[2] ACK  #1230 High CPU alert
Select (1-2) or q/!q to quit: 1
```

## Keyboard Controls

| Key | Action |
|-----|--------|
| `Tab` | Switch between shell and SRE panes |
| `Up/Down` | Scroll active pane |
| `Left/Right` | Command history (shell pane) |
| `PgUp/PgDn` | Fast scroll |
| `?` | Show help popup |

## Commands

### Shell Pane
| Command | Action |
|---------|--------|
| `!q` | Quit to incident list |

### SRE Pane
| Command | Action |
|---------|--------|
| `!n` | Ask for next steps |
| `!r` | Refresh analysis (syncs notes first) |
| `!h` | Show related past incidents |
| `!q` | Quit to incident list |
| Any text | Ask the SRE agent a question |

## How It Works

1. **Incident Selection**: Shows open PagerDuty incidents with color-coded status
2. **Initial Triage**: Fetches incident details, recent changes, related incidents
3. **SRE Analysis**: Sends context to PagerDuty Advance AI for root cause and next steps
4. **Command Capture**: Shell commands and output saved to incident notes
5. **Continuous Analysis**: Ask follow-up questions, notes sync before each query

## Shell Integration

### Bash (~/.bashrc)

```bash
export PAGERDUTY_USER_TOKEN="your-token"

# Optional alias
alias sre="sreshell"
```

### Zsh (~/.zshrc)

```bash
export PAGERDUTY_USER_TOKEN="your-token"

# Optional alias
alias sre="sreshell"

# Optional: function to start with incident number
srei() {
  echo "$1" | sreshell
}
```

### Fish (~/.config/fish/config.fish)

```fish
set -gx PAGERDUTY_USER_TOKEN "your-token"

# Optional alias
alias sre="sreshell"
```

## Troubleshooting

### "no open incidents found"
- Check your PagerDuty token has access to incidents
- Verify there are triggered/acknowledged incidents

### "Server error 502"
- PagerDuty Advance API temporarily unavailable
- Tool auto-retries 3 times, or use `!r` to retry manually

### Notes not syncing
- Ensure PAGERDUTY_EMAIL is set if using service account token
- Notes sync every 30 seconds or when asking SRE questions

## Source Code

```
sreshell/
├── main.go          # Main application (~2100 lines)
├── go.mod           # Go module definition
├── go.sum           # Dependency checksums
└── README.md        # This file
```

### Key Components

| Function | Description |
|----------|-------------|
| `main()` | Entry point, incident selection loop |
| `runIncidentSession()` | TUI session for single incident |
| `selectIncident()` | Colored incident picker |
| `handleShellInput()` | Shell pane input handling |
| `handleSREInput()` | SRE pane input handling |
| `querySREAgent()` | PagerDuty Advance MCP calls |
| `callStandardMCP()` | Standard PagerDuty MCP calls |
| `flushNotes()` | Sync commands to incident notes |
| `draw()` | TUI rendering |

### Building for Different Platforms

```bash
# macOS (Apple Silicon)
GOOS=darwin GOARCH=arm64 go build -o sreshell-darwin-arm64 main.go

# macOS (Intel)
GOOS=darwin GOARCH=amd64 go build -o sreshell-darwin-amd64 main.go

# Linux
GOOS=linux GOARCH=amd64 go build -o sreshell-linux-amd64 main.go
```

## License

MIT License - Copyright (c) fintonlabs.com
