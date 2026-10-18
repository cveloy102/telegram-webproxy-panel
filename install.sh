#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

REPOSITORY='cveloy102/telegram-webproxy-panel'
REF="${RELAY_PANEL_REF:-main}"
[[ "$REF" =~ ^[A-Za-z0-9._/-]+$ ]] || { echo 'Некорректная версия установщика.' >&2; exit 1; }

if [[ "${1:-}" == '--help' ]]; then
  echo 'Установка: bash install.sh. Восстановление: bash install.sh --recover. Нужны root, Ubuntu 24.04 amd64 и домен.'
  exit 0
fi
if (( EUID != 0 )); then
  echo 'Сначала войди в консоль VPS как root или выполни sudo -i, затем повтори команду.' >&2
  exit 1
fi
for tool in curl python3; do
  command -v "$tool" >/dev/null || { echo "Не найден $tool. Выполни: apt-get update && apt-get install -y curl python3" >&2; exit 1; }
done
work="$(mktemp -d /tmp/relay-panel-install.XXXXXXXX)"
trap 'rm -rf -- "$work"' EXIT
trap 'echo "Установка остановлена. Сообщение об ошибке — выше. Работающие ключи не сбрасываются." >&2' ERR

echo 'Скачиваю установщик и панель…'
curl --fail --silent --show-error --location --retry 3 --connect-timeout 15 --max-time 60 \
  --proto '=https' --proto-redir '=https' \
  "https://api.github.com/repos/$REPOSITORY/commits/$REF" -o "$work/commit.json"
commit="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["sha"])' "$work/commit.json")"
[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || { echo 'GitHub вернул некорректную версию.' >&2; exit 1; }
curl --fail --silent --show-error --location --retry 3 --connect-timeout 15 --max-time 180 \
  --proto '=https' --proto-redir '=https' \
  "https://codeload.github.com/$REPOSITORY/tar.gz/$commit" -o "$work/source.tar.gz"
python3 - "$work" <<'PY'
import pathlib,sys,tarfile
root=pathlib.Path(sys.argv[1]); destination=root/'source';destination.mkdir()
with tarfile.open(root/'source.tar.gz') as archive:
    members=archive.getmembers()
    for item in members:
        parts=pathlib.PurePosixPath(item.name).parts
        if '..' in parts or item.name.startswith('/') or item.issym() or item.islnk() or not (item.isfile() or item.isdir()):
            raise SystemExit('Небезопасный путь в архиве. Установка остановлена.')
    archive.extractall(destination,filter='data')
directories=list(destination.iterdir())
if len(directories)!=1 or not directories[0].is_dir():raise SystemExit('Неожиданный формат архива.')
directories[0].rename(root/'project')
PY
python3 "$work/project/installer.py" --source "$work/project" --revision "$commit" "$@"
