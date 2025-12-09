# Project Tutwiler: Biosecurity Threat Intelligence Bot

A Python-based Slack bot that triages biosecurity threats using rule-based keyword matching and human-in-the-loop approval workflow. Built as a proof-of-concept for Bio-ISAC threat intelligence filtering.

## Problem Statement

Organizations like Bio-ISAC (Bioeconomy Information Sharing and Analysis Center) face a critical challenge: **too much noise**. Generic cyber threat feeds produce hundreds of alerts daily, but only a fraction are relevant to biosecurity—clinical diagnostics, biomanufacturing, agriculture, and food supply chains.

This project demonstrates a **Tier-1 triage assistant** that:
- Filters generic cyber alerts through a bio-relevant lens
- Uses explainable, rule-based scoring (not black-box ML)
- Surfaces HIGH/MEDIUM priority threats for human review
- Enforces human-in-the-loop approval before community distribution

The POC validates the pipeline architecture without touching real infrastructure or sensitive data.

## Features

- **Rule-Based Triage**: 8 keyword buckets covering clinical, biomanufacturing, agriculture, and severity domains
- **Automatic HIGH Triggers**: CVSS ≥ 9, outbreak language, sole-source dependencies, unpatched vulnerabilities
- **Slack Integration**: Posts draft alerts to moderator channel, waits for approval, publishes to community
- **Edit Path**: Moderators can reject and rewrite alerts before community posting
- **Web Dashboard**: Real-time visualization of threats, priorities, and approval status
- **Audit Trail**: Full state tracking in JSON for compliance and post-incident review

## Quick Start

```bash
# Clone and setup
git clone <repo-url>
cd 321-Group-Project-3

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp env.example .env
# Edit .env with your Slack credentials

# Run the bot
cd src
python bot.py

# Or run the dashboard
python dashboard.py
# Open http://localhost:5000
```

## Architecture

### Triage Model

**8 Keyword Buckets (grouped by impact):**

| Impact | Buckets |
|--------|---------|
| Clinical | `clinical_diagnostics` |
| Biomanufacturing | `sequencing_equipment`, `biomanufacturing_facilities` |
| Agriculture | `pasteurization_ics`, `dairy_livestock`, `food_supply_chain` |
| Severity | `outbreak_indicators`, `vulnerability_severity` |

**Automatic HIGH Triggers:**
- CVSS ≥ 9
- Keywords: `unpatch`, `no patch`, `infect`, `sole-source`, `multi-state`, `multi-country`, `outbreak`, `wastewater`

**Priority Rules:**
- **HIGH**: Any automatic trigger OR `buckets_hit >= 2` OR (`buckets_hit == 1` AND `keyword_count >= 7`)
- **MEDIUM**: `buckets_hit == 1` AND `keyword_count in [2..6]` OR CVSS 6-8
- **LOW**: Everything else (filtered out)

### System Flow

```
Threat Data → Triage Engine → Moderator Channel → Human Review → Community Channel
                   ↓                                    ↓
            bot_state.json ←──────── Approve/Edit/Reject
```

## Project Structure

```
.
├── data/
│   ├── critical_assets.json      # Keyword definitions for 8 buckets
│   ├── mock_threat_dataset.json  # Synthetic threat data (15 threats)
│   └── bot_state.json            # Runtime state (auto-generated)
├── src/
│   ├── bot.py                    # Main orchestrator (ThreatBot)
│   ├── triage_engine.py          # Rule-based triage logic
│   ├── slack_client.py           # Slack API wrapper
│   ├── utils.py                  # Text processing utilities
│   ├── dashboard.py              # Web dashboard (Flask)
│   ├── static/
│   │   ├── dashboard.js          # Dashboard interactivity
│   │   └── style.css             # Dashboard styling
│   └── templates/
│       └── dashboard.html        # Dashboard template
├── docs/                         # Documentation
├── scripts/
│   └── setup_instructions.md     # Setup guide
├── requirements.txt
├── env.example                   # Environment variable template
└── DASHBOARD_README.md           # Standalone dashboard docs
```

## Detailed Setup

### 1. Install Dependencies

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure Slack App

Create a Slack app at [api.slack.com/apps](https://api.slack.com/apps) with these bot token scopes:
- `chat:write`
- `channels:read`
- `channels:join`
- `im:write`
- `reactions:read`

Get your:
- **Bot Token** (starts with `xoxb-`)
- **Signing Secret**
- **Moderator Channel ID** (right-click channel → Copy link → extract ID)
- **Community Channel ID**

### 3. Configure Environment

```bash
cp env.example .env
```

Edit `.env`:
```
SLACK_BOT_TOKEN=xoxb-your-actual-token
SLACK_SIGNING_SECRET=your-actual-secret
SLACK_MODERATOR_CHANNEL=C01XXXXXXXXX
SLACK_COMMUNITY_CHANNEL=C02XXXXXXXXX
```

## Usage: Bot

### Run the Bot

```bash
cd src
python bot.py
```

The bot will:
1. Load threats from `data/mock_threat_dataset.json`
2. Triage each threat using rule-based scoring
3. Post HIGH/MEDIUM threats to moderator channel
4. Check for approval reactions (✅) or rejections (❌)
5. Post approved threats to community channel

### Moderator Actions

| Reaction | Action |
|----------|--------|
| ✅ | Approve and post as-is |
| ❌ + thread reply | Reject, use reply text as edited alert |
| ❌ only | Reject, do not post |

### Scheduled Execution

For automated runs, use cron:

```bash
# Run every hour
0 * * * * cd /path/to/project/src && /usr/bin/python bot.py
```

## Usage: Dashboard

### Run the Dashboard

```bash
cd src
python dashboard.py
```

Access at **http://localhost:5000**

### Dashboard Features

- **Statistics Panel**: Total threats, priority breakdown, pending approvals, average CVSS
- **Threat List**: Filter by priority, approval status, or search by title/description
- **Threat Details**: Full description, triage analysis, bucket hits, automatic triggers
- **Refresh Button**: Reload data without page refresh

The dashboard reads from the same JSON files as the bot—changes appear when you refresh.

## How Triage Works

### Text Preprocessing

1. Lowercase all text
2. Strip punctuation (preserve word boundaries)
3. Normalize whitespace
4. Stemmed substring matching (`infect` matches `infected`, `infection`)

### Example

**Threat Description:**
> "Unpatched vulnerability in clinical diagnostic equipment affecting patient systems. Multiple hospitals reported infected systems."

**Analysis:**
- `clinical_diagnostics` hits: 4 (diagnos, patient, hospital, infect)
- `vulnerability_severity` hits: 2 (unpatch, vulnerab)
- `buckets_hit`: 2
- **Automatic HIGH triggers**: `unpatch`, `infect`
- **Result**: HIGH PRIORITY

## Mock Data

All data in `/data` is **synthetic and safe**. No real threat intelligence sources are used.

### critical_assets.json

Defines keywords for each bucket:
```json
{
  "clinical_diagnostics": {
    "keywords": ["diagnos", "patient", "hospital", "laboratory", ...],
    "impact": "clinical"
  }
}
```

### mock_threat_dataset.json

15 synthetic threats covering:
- Critical hospital vulnerabilities
- Multi-state outbreak scenarios
- Bio-manufacturing ransomware
- ICS/SCADA exploits
- Low-priority maintenance items (for testing LOW filtering)

## Customization

### Adding Keywords

Edit `data/critical_assets.json`:
```json
{
  "your_category": {
    "keywords": ["keyword1", "keyword2"],
    "impact": "clinical|biomanufacturing|agriculture|severity"
  }
}
```

### Changing Priority Rules

Edit `src/triage_engine.py` and modify the scoring logic in `triage_threat()`.

### Custom Slack Formatting

Edit `src/slack_client.py` method `create_threat_blocks()` to customize Block Kit layout.

## Troubleshooting

### "SLACK_BOT_TOKEN not found"
Ensure `.env` file exists in project root and contains valid credentials.

### "Failed to post message"
- Check bot has proper OAuth scopes
- Verify channel IDs are correct (not channel names)
- Ensure bot is invited to both channels (`/invite @botname`)

### No approvals detected
- Bot checks for ✅ (`:white_check_mark:`) emoji reaction
- Ensure moderator reacts to the exact message posted by bot
- Run bot again to check for new approvals

### Dashboard shows no data
- Verify `data/mock_threat_dataset.json` exists and is valid JSON
- Check terminal for Flask errors
- Try `http://127.0.0.1:5000` if `localhost` doesn't work

## Development Guidelines

- **No external APIs**: All data is local and mock
- **No ML/AI**: Pure rule-based logic for explainability
- **Deterministic**: Same input always produces same output
- **Explainable**: Every decision traces back to specific keyword hits

## License

Educational project for MIS321 Group Project 3.
