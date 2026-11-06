# Deploying TRANA (Render, with a persistent disk)

The app keeps everything on its own disk: `backend/instance/trana.db` (users + encrypted papers),
`master.key` and `jwt.key`. So it needs a host with a **persistent disk** and **one worker**.
`render.yaml` in this repo already describes that service.

The `deploy-keys.local.env` file in the repo root holds the two keys you paste into Render.
It is git-ignored — never commit it, and keep a copy somewhere safe.

---

## 1. Get the code onto GitHub

Already done if `git push` succeeded. Otherwise run it in the project folder.

## 2. Create the service

1. Open <https://dashboard.render.com> on your phone browser (or a computer, it is easier).
2. **New** → **Blueprint**.
3. Connect the `trana` GitHub repository and approve access.
4. Render reads `render.yaml` and shows one service named **trana**. Click **Apply**.
5. When asked for the `sync: false` variables, paste these from `deploy-keys.local.env`:
   - `TRANA_MASTER_KEY`
   - `TRANA_JWT_SECRET`

   You can also leave them blank for now and fill them in later under
   **Environment** — the app simply generates its own keys on first boot.
   Leave the SMTP ones empty unless you want reset emails.
6. Wait for the build. It installs `backend/requirements.txt` and starts gunicorn.
   **Logs** shows progress; `Running on http://0.0.0.0:...` means it started.

## 3. Open it on your phone

Copy the service URL (`https://trana-xxxx.onrender.com`) and open it. Sign up there as
normal. That instance starts with an empty database — it is not your local data.

## 4. Point the app at its own address

In Render → the service → **Environment**, set both to the URL from step 3:

```
TRANA_BASE_URL=https://trana-xxxx.onrender.com
TRANA_CORS_ORIGINS=https://trana-xxxx.onrender.com
```

Save; Render redeploys. Without this, password-reset links point at `127.0.0.1:3000`.

## Rules that keep it working

- **Do not change `TRANA_MASTER_KEY` later.** Papers are encrypted with it; a new value
  makes every stored paper unreadable.
- **Keep one worker.** `--workers 1 --threads 4` in `render.yaml` is deliberate — SQLite
  with several processes will lock up.
- **Do not scale to more instances.** The disk belongs to a single instance.
- **Back up** `backend/instance/trana.db` occasionally (Render → Shell, or `scp` from your
  machine). The database *is* the papers.
- Free instance types have **no disk**: the app would lose data and keys on every restart.
  The `starter` plan in `render.yaml` is the cheapest one that keeps your data.

## Local use is unchanged

```
cd backend
.\venv\Scripts\python.exe app.py
```
Open <http://127.0.0.1:3000/>. Press `Ctrl+C` before starting it again.
