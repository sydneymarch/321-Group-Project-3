# Biosecurity Threat Intelligence Bot

A Python-based Slack bot that triages biosecurity threats using rule-based keyword matching and human-in-the-loop approval workflow.

## Overview

This bot:
1. Loads mock threat data from JSON files
2. Applies a 4-bucket rule-based triage system
3. Posts HIGH/MEDIUM priority threats to a Slack moderator channel
4. Monitors for approval reactions (✅)
5. Posts approved threats to a community channel

## Architecture

### Triage Model

**4 Keyword Buckets:**
- **Bucket A**: Clinical / Human Health
- **Bucket B**: Bio-Manufacturing
- **Bucket C**: Agriculture / Food Supply
- **Bucket D**: Severity / Patch Status

**Automatic HIGH Triggers:**
- Keywords: "unpatch", "no patch", "infect", "sole-source", "multi-state", "multi-country", "outbreak", "wastewater"
- CVSS >= 9

**Priority Rules:**
- **HIGH**: Any automatic trigger OR buckets_hit >= 2 OR (buckets_hit == 1 AND bucket_count >= 7)
- **MEDIUM**: buckets_hit == 1 AND bucket_count in [2..6] OR CVSS 6-8
- **LOW**: Everything else

### Project Structure

```
.
├── data/
│   ├── critical_assets.json      # Keyword definitions for 4 buckets
│   ├── mock_threat_dataset.json  # Synthetic threat data
│   └── bot_state.json           # Runtime state (auto-generated)
├── src/
│   ├── bot.py                   # Main orchestrator
│   ├── triage_engine.py         # Rule-based triage logic
│   ├── slack_client.py          # Slack API wrapper
│   └── utils.py                 # Text processing utilities
├── requirements.txt
└── env.example                  # Environment variable template
```

## Setup

### 1. Install Dependencies

```bash
python3 -m pip install -r requirements.txt
```

### 2. Configure Slack

Create a Slack app with the following bot token scopes:
- `chat:write`
- `channels:read`
- `channels:join`
- `im:write`
- `reactions:read`

Get your:
- Bot Token (starts with `xoxb-`)
- Signing Secret
- Moderator Channel ID
- Community Channel ID

### 3. Configure Environment

Copy `env.example` to `.env` and fill in your values:

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

## Usage

### Run the Bot

```bash
cd src
python bot.py
```

### What Happens

1. Bot loads threats from `data/mock_threat_dataset.json`
2. Triages each threat using rule-based scoring
3. Posts HIGH/MEDIUM threats to moderator channel
4. Waits for moderator to react with ✅
5. Posts approved threats to community channel

### Check Status

Add this to `bot.py`:
```python
if __name__ == '__main__':
    bot = ThreatBot()
    bot.status()  # Shows pending approvals
```

### Scheduled Execution

For scheduled runs, use cron:

```bash
# Run every hour
0 * * * * cd /path/to/project/src && /usr/bin/python bot.py
```

## How Triage Works

### Text Preprocessing
1. Lowercase
2. Strip punctuation
3. Normalize whitespace
4. Stemmed substring matching (e.g., "infect" matches "infected")

### Example

**Threat Description:**
> "Unpatched vulnerability in clinical diagnostic equipment affecting patient systems. Multiple hospitals reported infected systems."

**Analysis:**
- `A_count = 3` (diagnos, patient, hospital, infect)
- `D_count = 2` (unpatch, infect)
- `buckets_hit = 2`
- **Automatic HIGH trigger**: "unpatch", "infect"
- **Result**: HIGH PRIORITY

## Mock Data

All data in `/data` is **synthetic and safe**. No real threat intelligence sources are used.

### critical_assets.json
Defines keywords for each bucket with impact classifications.

### mock_threat_dataset.json
Contains 13 synthetic threats covering various scenarios:
- High-priority CVEs
- Multi-state outbreaks
- Bio-manufacturing incidents
- Low-priority maintenance items

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

## Development Guidelines

- **No external APIs**: All data is local and mock
- **No ML/AI**: Pure rule-based logic
- **Deterministic**: Same input always produces same output
- **Explainable**: Every decision has clear reasoning

## Troubleshooting

### "SLACK_BOT_TOKEN not found"
Ensure `.env` file exists and contains valid credentials.

### "Failed to post message"
- Check bot has proper permissions
- Verify channel IDs are correct
- Ensure bot is invited to channels

### No approvals detected
- Bot checks for ✅ (`:white_check_mark:`) emoji reaction
- Ensure moderator reacts to the exact message posted by bot
- Run bot again to check for new approvals

## License

Educational project for MIS321 Group Project 3.
