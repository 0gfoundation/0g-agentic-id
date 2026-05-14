#!/bin/bash
set -e

# OpenClaw gateway startup script.
# API keys (ANTHROPIC_API_KEY, OPENAI_API_KEY, etc.) are read directly
# from environment variables by openclaw — no explicit config injection needed.

exec openclaw gateway run --allow-unconfigured --bind lan --port 3284
