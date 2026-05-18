# BOT VENDAS PRO V14

A Discord sales bot with PIX payment integration, support tickets, and product panel management.

## Setup

1. Set the `DISCORD_TOKEN` secret in the Replit Secrets tab.
2. Optionally set additional environment variables (see below).
3. Run the bot with `python bot.py`.

## Environment Variables

- `DISCORD_TOKEN` (required) — Your Discord bot token from the Developer Portal.
- `PIX_KEY` — Your PIX key for payments.
- `PIX_NOME` — Recipient name (max 25 chars).
- `PIX_CIDADE` — City (max 15 chars).
- `WEBHOOK_URL` — Discord webhook URL for logs.
- `OWNER_IDS` — Comma or semicolon-separated Discord user IDs with owner-level access.
- `TICKET_IMAGE_URL` — Banner image URL for ticket panels.
- `TICKET_THUMB_URL` — Thumbnail URL for ticket panels.
- `TICKET_CATEGORY_NAME` — Category name for ticket channels (default: `tickets`).
- `TICKET_PANEL_TITLE` — Title for ticket panels.
- `TICKET_PANEL_DESC` — Description for ticket panels.

## Project Structure

- `bot.py` — Main bot logic (Discord commands, Flask keep-alive server, SQLite DB).
- `vendas.db` — SQLite database (products, panels, orders, reviews, guild config).
- `requirements.txt` — Python dependencies.

## Key Features

- Product panels with dropdown selectors
- PIX QR code payment generation
- Support ticket system (suporte, dúvidas, financeiro)
- Sales statistics and reviews
- Persistent views after bot restart

## User Preferences

- Python 3.12 runtime (as configured in `.replit`)
