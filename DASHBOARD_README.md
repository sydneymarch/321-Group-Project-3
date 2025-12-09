# Threat Intelligence Dashboard

A web-based dashboard to visualize and monitor biosecurity threats processed by the Slack bot.

## Features

- **Real-time Statistics**: View overview of threats by priority, approval status, and CVSS scores
- **Threat List**: Browse all threats with filtering and search capabilities
- **Detailed Views**: Click any threat to see full details including triage analysis
- **Approval Tracking**: See which threats are pending approval, approved, or not yet posted
- **Responsive Design**: Works on desktop and mobile devices

## Installation

1. Install Flask (if not already installed):
```bash
pip3 install -r requirements.txt
```

## Running the Dashboard

1. Navigate to the project directory:
```bash
cd 321-Group-Project-3
```

2. Run the dashboard:
```bash
cd src
python3 dashboard.py
```

3. Open your web browser and go to:
   - **http://localhost:5000**
   - **http://127.0.0.1:5000**

## URL to Access

Once the dashboard is running, you can access it at:

**http://localhost:5000**

or

**http://127.0.0.1:5000**

## Features Overview

### Statistics Dashboard
- Total threats count
- Breakdown by priority (HIGH, MEDIUM, LOW)
- Pending approvals count
- Approved threats count
- Average CVSS score

### Threat List
- Filter by priority level
- Filter by approval status
- Search by title, ID, or description
- View detailed information for each threat

### Threat Details
- Full threat description
- Triage analysis and explanation
- Bucket hit counts
- Automatic triggers
- Approval status and timestamps

## Stopping the Dashboard

Press `Ctrl+C` in the terminal where the dashboard is running.

## Notes

- The dashboard reads data from the same JSON files the bot uses
- It shows real-time data from `data/mock_threat_dataset.json`
- Approval status comes from `data/bot_state.json` (if the bot has been run)
- The dashboard updates when you refresh the page or click the "Refresh" button

