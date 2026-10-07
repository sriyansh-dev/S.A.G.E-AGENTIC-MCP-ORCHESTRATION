# Live demo runbook (CachyOS · Fish · VS Code)

## One-time prep (before the presentation day)
1. Create the demo target on GitHub (from the `sage-demo-repo` folder):
   ```fish
   cd sage-demo-repo
   git init -b main; and git add -A; and git commit -m "demo: buggy inventory app"
   gh repo create sage-demo --public --source=. --push
   ```
   It has 5 failing tests, a shell-injection bug and an unsafe `yaml.load` — S.A.G.E. should fix all of it and verify with pytest.
2. `gh auth status` must say you are logged in (`gh auth login --web -h github.com -p https` if not).
3. Do one full rehearsal on the same Wi-Fi. Close the rehearsal PR afterwards: `gh pr close <n> --delete-branch -R <you>/sage-demo`.

## At the venue (everything was closed)
1. Open VS Code → **File → Open Folder →** your S.A.G.E. project folder.
2. Open the terminal (Ctrl+`) and activate the environment:
   ```fish
   source .venv/bin/activate.fish
   ```
   (If `.venv` is missing: `fish bootstrap.fish`.)
3. Check GitHub: `gh auth status`
4. Set a **fresh** Groq key — same line, paste with **Ctrl+Shift+V**, then Enter (it is gone after a reboot/new terminal):
   ```fish
   set -x GROQ_API_KEY 
   ```
5. Run:
   ```fish
   python -m sage --repo https://github.com/<you>/sage-demo --goal "fix failing tests and security issues"
   ```
6. Show the **LIVE DASHBOARD** URL it prints (Ctrl+Shift+P → *Simple Browser: Show* → paste, or the browser tab that opens).
7. Narrate while it runs: clone → scan ∥ analyze ∥ install → code review → baseline (5 failures) → plan → patch → review → tests pass.
8. When it finishes: open the printed **PR link**, show `SAGE_REPORT.md`, then in the VS Code window it opens run:
   ```fish
   python main.py          # totals are now correct
   python -m pytest -q     # 7 passed
   ```

## If something goes wrong
| Problem | Do this |
|---|---|
| No Wi-Fi / GitHub down | `--dry-run` shows everything except the push; keep screenshots of a good run as backup |
| Groq rate limit | wait 60 s (it retries by itself) or add `--runs 1` |
| Wrong model error | don't pass `--model`; the tool picks one |
| Patch not found in 3 tries | rerun with `--max-iterations 4` |
