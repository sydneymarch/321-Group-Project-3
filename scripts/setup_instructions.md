# Setup Instructions

## Quick Start

### 1. Install Python Dependencies

```bash
pip install -r requirements.txt
```

This installs:
- `slack_sdk` - Slack API client
- `python-dotenv` - Environment variable management

### 2. Set Up Slack App

1. Go to [api.slack.com/apps](https://api.slack.com/apps)
2. Click "Create New App" → "From scratch"
3. Name it (e.g., "Threat Intelligence Bot")
4. Select your workspace

#### Configure OAuth Scopes

Under "OAuth & Permissions", add these Bot Token Scopes:
- `chat:write` - Post messages
- `channels:read` - Read channel info
- `channels:join` - Join channels
- `im:write` - Send DMs
- `reactions:read` - Read emoji reactions

#### Install App to Workspace

1. Click "Install to Workspace"
2. Authorize the app
3. Copy the "Bot User OAuth Token" (starts with `xoxb-`)

#### Get Signing Secret

Under "Basic Information", find "Signing Secret" and copy it.

### 3. Get Channel IDs

For both your moderator and community channels:

1. Open Slack desktop/web app
2. Right-click the channel name
3. Select "View channel details"
4. Scroll to bottom and click "Channel ID"
5. Copy the ID (format: `C01XXXXXXXXX`)

### 4. Configure Environment

```bash
# Copy the example file
cp env.example .env

# Edit with your values
nano .env  # or use any text editor
```

Fill in:
```
SLACK_BOT_TOKEN=xoxb-your-actual-token-here
SLACK_SIGNING_SECRET=your-actual-secret-here
SLACK_MODERATOR_CHANNEL=C01XXXXXXXXX
SLACK_COMMUNITY_CHANNEL=C02XXXXXXXXX
```

### 5. Invite Bot to Channels

In Slack, invite the bot to both channels:
```
/invite @YourBotName
```

### 6. Test the Bot

```bash
cd src
python bot.py
```

You should see output like:
```
============================================================
THREAT INTELLIGENCE BOT - RUN STARTED
Time: 2025-11-23 10:30:00
============================================================

=== Loading and Triaging Threats ===
Loaded 13 threats from dataset
Found 8 HIGH/MEDIUM priority threats
  TUT-001: Posting to moderator channel (HIGH priority)
    ✓ Posted successfully (ts: 1234567890.123456)
...
```

### 7. Approve a Threat

1. Go to your moderator channel in Slack
2. Find the bot's message
3. React with ✅ emoji
4. Run bot again: `python bot.py`
5. Approved threat will be posted to community channel

## Scheduled Execution

### Using Cron (Linux/Mac)

Edit crontab:
```bash
crontab -e
```

Add line to run every hour:
```
0 * * * * cd /path/to/321-Group-Project-3/src && /usr/bin/python3 bot.py >> /tmp/threat-bot.log 2>&1
```

### Using Task Scheduler (Windows)

1. Open Task Scheduler
2. Create Basic Task
3. Trigger: Hourly
4. Action: Start a program
   - Program: `python.exe`
   - Arguments: `bot.py`
   - Start in: `C:\path\to\321-Group-Project-3\src`

## Troubleshooting

### Import Error: No module named 'slack_sdk'

```bash
pip install -r requirements.txt
```

### KeyError: 'SLACK_BOT_TOKEN'

Your `.env` file is missing or not in the right location. Ensure:
- File is named exactly `.env` (not `.env.txt`)
- File is in the project root directory
- Environment variables are set correctly

### "Failed to post message: not_in_channel"

Invite the bot to the channel:
```
/invite @YourBotName
```

### Bot posts but doesn't detect approvals

- Ensure you're using the ✅ emoji (`:white_check_mark:`)
- Run the bot again after reacting - it only checks on each run
- Check that reactions were added to the bot's message, not a reply

### "Error loading threats" or "Error loading critical assets"

Check that the JSON files in `/data` are valid:
```bash
python -m json.tool data/critical_assets.json
python -m json.tool data/mock_threat_dataset.json
```

## Testing Without Slack

To test triage logic without posting to Slack:

Create `test_triage.py`:
```python
import json
from triage_engine import triage_all_threats

# Load threats
with open('../data/mock_threat_dataset.json') as f:
    threats = json.load(f)

# Triage
results = triage_all_threats(threats)

# Print results
for threat, result in results:
    print(f"\n{threat['id']}: {result['priority']}")
    print(f"  {threat['title']}")
    print(f"  {result['explanation']}")
```

Run:
```bash
cd src
python test_triage.py
```

## Next Steps

- Review triage results in `data/bot_state.json`
- Customize keywords in `data/critical_assets.json`
- Add more mock threats to `data/mock_threat_dataset.json`
- Modify Slack message formatting in `src/slack_client.py`

