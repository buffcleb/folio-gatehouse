#!/usr/bin/env bash
#
# svn-assets.sh — Publish Folio Gatehouse directory artwork to WordPress.org.
#
# Plugin assets (banners, icons, screenshots) live in the SVN repo's top-level
# /assets directory — NOT in trunk — and are never bundled into the plugin zip.
# This script syncs the Git-tracked assets/ folder there and commits.
#
# Usage:
#   bin/svn-assets.sh        # sync assets/ → SVN /assets, confirm, commit
#   bin/svn-assets.sh -y     # skip the confirmation prompt
#
# Prerequisites:
#   - svn installed
#   - WordPress.org commit access active for user "buffcleb"
#
set -euo pipefail

SVN_URL="https://plugins.svn.wordpress.org/folio-gatehouse"
SVN_USER="buffcleb"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="${REPO_ROOT}/assets"
SVN_WC="${REPO_ROOT}/../.folio-gatehouse-svn"

ASSUME_YES=0
[[ "${1:-}" == "-y" || "${1:-}" == "--yes" ]] && ASSUME_YES=1

if [[ ! -d "$SRC" ]]; then
    echo "✗ No assets/ folder at ${SRC}." >&2
    exit 1
fi

echo "→ Assets source : $SRC"
echo "→ SVN working   : $SVN_WC"
echo

# Checkout or update the SVN working copy (shared with svn-deploy.sh).
if [[ -d "${SVN_WC}/.svn" ]]; then
    echo "→ Updating existing SVN checkout…"
    svn update --username "$SVN_USER" "$SVN_WC"
else
    echo "→ Checking out SVN repo (first run)…"
    svn checkout --username "$SVN_USER" "$SVN_URL" "$SVN_WC"
fi

mkdir -p "${SVN_WC}/assets"

# Sync artwork into the SVN assets dir (delete removed files, keep .svn metadata).
echo "→ Syncing artwork into assets…"
rsync -a --delete --exclude='.svn' "${SRC}/" "${SVN_WC}/assets/"

cd "$SVN_WC"
svn add --force assets >/dev/null
MISSING="$(svn status assets | awk '/^!/{print $2}')"
if [[ -n "$MISSING" ]]; then
    echo "→ Removing deleted assets from SVN:"
    echo "$MISSING" | sed 's/^/   /'
    echo "$MISSING" | xargs -I{} svn rm "{}" >/dev/null
fi

echo
echo "──────── Pending asset changes ────────"
svn status assets
echo "───────────────────────────────────────"
echo

if [[ "$ASSUME_YES" -ne 1 ]]; then
    read -r -p "Commit these assets to WordPress.org? [y/N] " ans
    [[ "$ans" == "y" || "$ans" == "Y" ]] || { echo "Aborted — nothing committed."; exit 1; }
fi

svn commit --username "$SVN_USER" -m "Update plugin directory assets"
echo "✓ Assets published. They appear on the listing within a few minutes:"
echo "  https://wordpress.org/plugins/folio-gatehouse"
