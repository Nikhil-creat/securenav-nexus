# Deploy the live demo to GitHub Pages (from Termux or any shell)

The site lives in `docs/` (single `index.html`, no build step). GitHub Pages serves it free at
`https://<your-username>.github.io/<repo-name>/`.

## 1. Push the repo
```bash
pkg install git unzip -y                 # Termux, first time only
unzip securenav-nexus-master.zip && cd securenav-nexus
git init -b main
git config user.name "Nikhil Chary Sriramoju" && git config user.email "sriramojunikhil66@gmail.com"
git add . && git commit -m "SecureNav-NEXUS Ultimate: platform + live demo"
# create an EMPTY repo named securenav-nexus on github.com first (no README), then:
git remote add origin https://github.com/Nikhil-creat/securenav-nexus.git
git push -u origin main                  # use a Personal Access Token as the password
```

## 2. Turn on Pages
GitHub repo → **Settings → Pages → Build and deployment → Source: Deploy from a branch →
Branch: `main`, folder: `/docs` → Save**. After about a minute your site is live at
`https://nikhil-creat.github.io/securenav-nexus/`.

## 3. Use the Groq assistant on the live site
1. Create a free key at https://console.groq.com/keys (starts with `gsk_`).
2. Open your site → **AI Copilot** → paste the key → **Save**.
The key stays in your browser's localStorage and goes only to api.groq.com. **Never put it in the repo.**
Anyone visiting your public site must paste their own key to use full Groq mode; without one they get the offline copilot.

## 4. Update later
```bash
git add . && git commit -m "update" && git push
```

## Troubleshooting
- 404 after enabling Pages: wait 1-2 min, confirm `docs/index.html` exists on `main`.
- Groq 401: key mistyped or revoked. 429: free-tier rate limit; wait a minute.
- Run locally: `cd docs && python3 -m http.server 8000` then open http://localhost:8000
