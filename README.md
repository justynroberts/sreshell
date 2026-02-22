# SREShell

A split-pane troubleshooting shell for PagerDuty incidents. Run commands on the left, get AI-powered SRE analysis on the right.

**Repository**: https://github.com/justynroberts/sreshell

## Quick Start

### 1. Download

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

### 2. Configure

```bash
# Get a PagerDuty User Token:
# PagerDuty -> My Profile -> User Settings -> Create API User Token

# Add to your shell config (~/.zshrc or ~/.bashrc)
export PAGERDUTY_USER_TOKEN="u+your-token-here"
```

### 3. Install (optional)

```bash
sudo mv sreshell /usr/local/bin/
# Or: mv sreshell ~/bin/
```

### 4. Run

```bash
sreshell
```

## Features

- **Split-pane TUI** - Shell (60%) + SRE agent (40%)
- **Tmux integration** - Full shell experience with your prompt, aliases, colors
- **Auto-triage** - Root cause analysis and numbered next steps on incident load
- **Note sync** - Commands saved to incident notes (individually, not batched)
- **Retry logic** - Auto-retries on network errors and 5xx responses
- **Color-coded incidents** - Red (triggered), Yellow (acknowledged)

## Requirements

- PagerDuty account with API access
- PagerDuty Advance license (for AI features)
- tmux (recommended) - `brew install tmux` or `apt install tmux`

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `PAGERDUTY_USER_TOKEN` | Yes* | User API token (recommended) |
| `PAGERDUTY_TOKEN` | Yes* | Alternative: general API token |
| `PAGERDUTY_REGION` | No | Set to `eu` for EU region |
| `PAGERDUTY_EMAIL` | No | Email for note attribution |

*One of `PAGERDUTY_USER_TOKEN` or `PAGERDUTY_TOKEN` is required.

## Keyboard Controls

| Key | Action |
|-----|--------|
| `Tab` | Switch between shell and SRE panes |
| `Up/Down` | Scroll active pane |
| `Left/Right` | Command history (shell pane) |
| `PgUp/PgDn` | Fast scroll |
| `Ctrl+N` | Ask for next steps (SRE pane) |
| `?` | Show help popup |

## Commands

### Shell Pane

| Command | Action |
|---------|--------|
| `!q` | Return to incident list |
| Any command | Runs in shell, saved to notes |

### SRE Pane

| Command | Action |
|---------|--------|
| `!n` | Get next steps |
| `!r` | Refresh analysis (syncs notes first) |
| `!h` | Show related past incidents |
| `!q` | Return to incident list |
| Any text | Ask the SRE agent |

## How It Works

1. **Select incident** - Choose from open incidents (color-coded by status)
2. **Auto-triage** - Fetches context, runs initial analysis with root cause + next steps
3. **Run commands** - Shell commands are captured and saved to incident notes
4. **Ask questions** - Notes sync before each SRE query (2s delay for indexing)
5. **Iterate** - Continue troubleshooting with full context preserved

## Building from Source

```bash
git clone https://github.com/justynroberts/sreshell.git
cd sreshell
go build -o sreshell main.go
```

### Cross-compile

```bash
# macOS Apple Silicon
GOOS=darwin GOARCH=arm64 go build -o sreshell-darwin-arm64 main.go

# macOS Intel
GOOS=darwin GOARCH=amd64 go build -o sreshell-darwin-amd64 main.go

# Linux x86_64
GOOS=linux GOARCH=amd64 go build -o sreshell-linux-amd64 main.go
```

## Troubleshooting

### "no open incidents found"
- Verify your token has incident access
- Check there are triggered/acknowledged incidents in PagerDuty

### "Server error 502" or "EOF"
- PagerDuty Advance API temporarily unavailable
- Auto-retries 3 times with backoff
- Use `!r` to retry manually

### Shell doesn't show my prompt/colors
- Install tmux: `brew install tmux` (macOS) or `apt install tmux` (Linux)
- SREShell uses tmux for full shell experience
- Falls back to basic shell if tmux unavailable

### Notes not appearing in PagerDuty
- Notes sync every 30 seconds or before SRE queries
- Each command+response is saved as a separate note
- Shell prompts are automatically stripped from notes

## License

MIT License - Copyright (c) fintonlabs.com
