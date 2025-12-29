# POINT Pool & Lounge Live Wall

## Product Goal
Interactive live wall for POINT Pool & Lounge: guests send messages from their phones that appear on the stage LCD after moderator approval (default). Must run smoothly on local venue hardware and hosted environments, and remain resilient against spam, bots, and abusive use of public endpoints.

## Operating Targets
- Reliable on local venue mini PC/laptop servers.
- Works when hosted with domain + HTTPS.
- Hardening for abuse: rate limiting, cooldowns, filters, and endpoint protection.
- Pleasant UX for staff (Admin/Moderator) and a visually striking screen mode.

## Modes & Pages
1. **Guest Entry** (`/guest/login.html`)
   - Inputs: Event code + nickname; mandatory disclaimer checkbox.
   - Confirm button enabled only when valid; creates session token stored in `localStorage`.
   - QR parameters carry event code and optional table identifier.
2. **Guest Chat** (`/guest/chat.html`)
   - Displays approved feed; message input with pending/approved toasts, smart autoscroll, and lightweight emoji picker.
   - No DMs, replies, or media uploads.
3. **Staff Login** (`/admin/` or `/admin/index.html`)
   - Single login gate for SuperAdmin/Admin/Moderator; dashboard menus adjust per role (SuperAdmin sees full menu).
4. **Screen / LCD Mode** (`/screen/`)
   - Big-screen layout with rolling 10-item bubble feed, 15s highlight, smoothed blurred video background, optional logo/title/performer overlay.

## Roles & Access
- **SuperAdmin**: manage staff, full settings/branding, audit log viewer, tools (backup/restore/export/panic).
- **Admin**: moderation, branding, screen settings, read-only audit log.
- **Moderator**: moderation only (approve/reject/view feed), no global settings changes.

## Message Lifecycle
- Default: guest sends → `pending`; moderator/admin approve → `approved` → realtime broadcast to Screen & Guest; reject → `rejected`.
- `auto_accept=true`: guest send → `approved` + broadcast.
- Audit/safety fields: `approved_by`, `approved_at`, `session_id`, `ip_hash`.

## System Architecture
- Backend: Node.js + Express; Realtime: Socket.IO; DB: SQLite (`better-sqlite3`); Frontend: vanilla SPA in `public`; Uploads: local files with URLs in settings.
- Stable core APIs; UI can evolve without creating new endpoints.

## Public Routes (must be honored)
Static pages: `/guest/login.html`, `/guest/chat.html`, `/admin/`, `/screen/`.

API endpoints:
- `GET /api/health`
- `POST /api/auth/login`
- `POST /api/public/session`
- `POST /api/public/message` (header `X-Session`)
- `GET /api/screen/messages?limit=...`
- `GET /api/mod/messages?status=pending&limit=...`
- `POST /api/mod/messages/:id/approve`
- `POST /api/mod/messages/:id/reject`
- `GET /api/settings`
- `POST/PUT /api/settings`
- `GET /api/admin/qrcodes`
- `GET /api/admin/audit`
- `GET /api/admin/staff` (SuperAdmin only)
- `POST /api/admin/staff` (SuperAdmin only)
- `PUT /api/admin/staff/:id` (SuperAdmin only)

## Realtime Events
- `settings:update` pushes global settings to screen/admin/guest.
- `message:approved` pushes full message payload so Screen & Guest update without reload; polling allowed as fallback.

## Guardrails
- Required: rate limit public routes, per-session cooldown (~5s), message length cap (160–220), duplicate hash detection, bad-words filter, moderation on by default.
- Bonus: slowmode toggle, blocklist for nickname/session.

## Branding & Theme
- Single-source settings applied to all pages: `brand.title`, `brand.subtitle`, `assets.logo_url`, `assets.bg_url`, `assets.video_url`, `assets.performer_url` (+ toggle).
- Theme: navy/charcoal base with white text; accents of billiard-blue and neon purple; consistent glass effect.

## UI/UX Notes
- Guest Entry: one-screen CTA, disabled confirm until valid, clear feedback.
- Guest Chat: WhatsApp-style bubbles; different colors for guest vs official; smart autoscroll; light emoji picker.
- Moderator Dashboard: focus on pending queue; large Approve/Reject buttons; hotkeys A/R and `/` search; skeletons and toasts.
- Screen: smoothed video with blur overlay; max 10 rolling bubbles; 15s highlight (official can prioritize); panic states for pause/blackout.

## Hosting vs Local
- Local: server on venue mini PC; guests access over venue Wi-Fi; screen via HDMI browser.
- Hosting: domain + HTTPS; persistent DB and uploads (volume); tighter guardrails.

## Development Constraints
- Freely iterate on UI/UX, wiring to existing endpoints, and realtime listeners.
- Avoid altering core endpoint structure or DB schema without planned migrations.

## Pre-Feature Checklist
- Guest login → session → chat without errors.
- Guest send → pending/approved according to mode.
- Moderator approve → screen & guest update realtime.
- Admin branding update → screen/guest reflect changes (logo/bg/video/performer).
- Screen rolling + highlight stable.
- Staff menus respect role visibility/permissions.

## Running the app locally

```bash
npm install
npm run start
# app listens on http://localhost:3000
```

Default seeded staff accounts (change in production):

- superadmin / superadmin
- admin / admin
- moderator / moderator

Public URLs for manual checks:

- Guest entry: `http://localhost:3000/guest/login.html`
- Guest chat: `http://localhost:3000/guest/chat.html`
- Staff dashboard: `http://localhost:3000/admin/`
- Screen mode: `http://localhost:3000/screen/`
