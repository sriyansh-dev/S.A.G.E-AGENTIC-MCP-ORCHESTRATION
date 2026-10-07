#!/usr/bin/env fish
# S.A.G.E. bootstrap — CachyOS / Arch Linux, fish shell.
set -l root (dirname (status filename))
cd $root; or exit 1

# system packages (kdialog for KDE, zenity otherwise; github-cli supplies local GitHub credentials)
sudo pacman -S --needed --noconfirm git github-cli python python-pip fish kdialog zenity; or exit 1

python -m venv .venv; or exit 1
source .venv/bin/activate.fish; or exit 1
pip install --quiet -r requirements.txt; or exit 1

gh auth status >/dev/null 2>&1; or gh auth login; or exit 1

echo "ready. run:"
echo "  source $root/.venv/bin/activate.fish"
echo "  python -m sage            # prompts: Groq key (hidden), repo URL, goal"
