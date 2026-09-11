# QA Test App

A small Flask app built specifically to act as a **test target** for an agentic QA/testing system. It covers registration, login (with a math captcha), a protected dashboard, and a forgot/reset password flow — all designed to give a QA agent realistic positive and negative cases to exercise.

## Run it locally

```bash
pip install -r requirements.txt
python app.py
```
(Use `python`, not `python3`, if you're inside a Windows venv.)

The app starts at **http://127.0.0.1:5000** (data is stored in a local `app.db` SQLite file, created automatically on first run).

To reset all data, just delete `app.db` and restart.

## Getting a public URL (optional, for a remote agent)

- **ngrok** — run `ngrok http 5000` while the app is running locally for a quick temporary public URL.
- **Render.com** / **Railway.app** — connect this folder as a repo for a permanent free-tier URL.

Ask me and I can walk you through whichever one you pick.

---

## Requirements spec (give this to your QA agent)

### Pages
| Page | URL | Description |
|---|---|---|
| Registration | `/register` | Form: full name, email, password, **captcha**. Creates a new account. |
| Login | `/login` | Form: email, password, **captcha**. Starts a session and redirects to dashboard. Has a "Forgot password?" link. |
| Dashboard | `/dashboard` | Protected — redirects to `/login` if not authenticated. Shows profile info loaded via API. |
| Forgot password | `/forgot-password` | Form: email. Generates a reset link (shown on screen — no real email server). |
| Reset password | `/reset-password?token=...` | Form: new password + confirm. Consumes the token from the link above. |

### API endpoints
| Method | Endpoint | Auth required | Purpose |
|---|---|---|---|
| GET | `/api/captcha` | No | Issues a new math captcha challenge tied to the session: `{captcha_id, question}` |
| POST | `/api/register` | No | Create account. Body: `{full_name, email, password, captcha_id, captcha_answer}` |
| POST | `/api/login` | No | Authenticate, starts session. Body: `{email, password, captcha_id, captcha_answer}` |
| GET | `/api/profile` | Yes (session) | Returns the logged-in user's profile as JSON |
| POST | `/api/logout` | Yes (session) | Ends the session |
| POST | `/api/forgot-password` | No | Body: `{email}`. Always returns a generic success message. If the email exists, also returns `reset_link` / `reset_token` directly (simulating the email step, since there's no mail server). |
| POST | `/api/reset-password` | No | Body: `{token, new_password, confirm_password}`. Consumes the token and updates the password. |

### Captcha behavior (important for test design)
- Each captcha is a simple math question ("What is 7 + 2?"), tied to the current session cookie.
- **Single-use**: once submitted (correct or not), that `captcha_id` is invalidated — a new one must be fetched via `GET /api/captcha` before the next attempt.
- **Expires after 5 minutes** if unused.
- Register/login calls without a valid `captcha_id`/`captcha_answer` pair are rejected with `400`.

### Password reset behavior
- Reset tokens are single-use and expire after **30 minutes**.
- `/api/forgot-password` always returns the same generic message whether or not the email exists (no user enumeration) — but for testing purposes, the actual `reset_link`/`reset_token` is returned directly in the response *only* when the account exists.

### Validation rules (intentional, for testing negative cases)
- `full_name`, `email`, `password` all required on register → missing any → `400`
- Email must match a basic `x@y.z` pattern → `400` if invalid
- Password must be **at least 6 characters** (applies to register and reset) → `400` if shorter
- Registering with an email that already exists → `409 Conflict`
- Logging in with wrong email/password → `401 Unauthorized`
- Missing, wrong, reused, or expired captcha → `400`
- Calling `/api/profile` or `/api/logout` without a valid session → `401 Unauthorized`
- Visiting `/dashboard` without a session → redirects to `/login`
- Reset with invalid/expired/already-used token → `400`
- Reset with mismatched `new_password`/`confirm_password` → `400`

### Suggested test scenarios for the agent
1. Register a new user with valid data + correct captcha → `201`.
2. Register again with the same email → `409`.
3. Register with a 3-character password → `400`.
4. Register with a malformed email → `400`.
5. Register with a wrong captcha answer → `400`.
6. Try to reuse a captcha_id from a previous (successful or failed) attempt → `400`.
7. Log in with correct credentials + correct captcha → `200`, redirected to dashboard.
8. Log in with wrong password → `401`.
9. Visit `/dashboard` while logged in → profile data renders correctly.
10. Visit `/dashboard` directly without logging in → redirects to `/login`.
11. Call `/api/profile` without a session cookie → `401`.
12. Request `/api/forgot-password` for a registered email → get a reset link back.
13. Request `/api/forgot-password` for an unregistered email → same generic message, no link.
14. Use the reset link/token with mismatched new/confirm passwords → `400`.
15. Use the reset link/token correctly → `200`, then confirm old password no longer logs in and new password does.
16. Reuse the same reset token a second time → `400` (already used).
17. Wait past the captcha/token expiry window (or manually test with an old token) → confirm expired-token/expired-captcha error paths.
