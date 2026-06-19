#!/usr/bin/env bash
#
# svn-deploy.sh — Publish the Folio Gatehouse plugin to the WordPress.org SVN repo.
#
# Source of truth is the Git-tracked plugin folder. This script syncs that
# folder into the SVN trunk, reconciles adds/deletes, copies trunk to a
# version tag, and (after confirmation) commits to WordPress.org.
#
# Usage:
#   bin/svn-deploy.sh            # version read from the plugin header
#   bin/svn-deploy.sh 1.1.8      # force a specific version
#   bin/svn-deploy.sh -y         # skip the confirmation prompt before commit
#
# Prerequisites:
#   - svn installed (xcode-select --install, or `brew install svn`)
#   - WordPress.org commit access active for user "buffcleb"
#   - The Git plugin folder is committed and matches what you intend to ship
#
set -euo pipefail

# ─── Config ────────────────────────────────────────────────────────────────────
SVN_URL="https://plugins.svn.wordpress.org/folio-gatehouse"
SVN_USER="buffcleb"

# Git-tracked plugin folder = source of truth (chosen workflow).
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="${REPO_ROOT}/folio-gatehouse"

# SVN working copy lives OUTSIDE the Git repo to avoid nesting.
SVN_WC="${REPO_ROOT}/../.folio-gatehouse-svn"

# ─── Args ──────────────────────────────────────────────────────────────────────
ASSUME_YES=0
VERSION=""
for arg in "$@"; do
    case "$arg" in
        -y|--yes) ASSUME_YES=1 ;;
        *)        VERSION="$arg" ;;
    esac
done

# ─── Resolve version from the plugin header if not passed ──────────────────────
if [[ -z "$VERSION" ]]; then
    VERSION="$(grep -m1 -E '^\s*\*?\s*Version:' "${SRC}/role-folder-protection.php" \
               | sed -E 's/.*Version:[[:space:]]*([0-9][0-9.]*).*/\1/')"
fi
if [[ ! "$VERSION" =~ ^[0-9]+(\.[0-9]+)*$ ]]; then
    echo "✗ Could not determine a valid version (got: '$VERSION')." >&2
    exit 1
fi

# ─── Sanity: readme Stable tag should match the version being shipped ──────────
STABLE_TAG="$(grep -m1 -E '^Stable tag:' "${SRC}/readme.txt" | sed -E 's/Stable tag:[[:space:]]*//' | tr -d '[:space:]')"
if [[ "$STABLE_TAG" != "$VERSION" ]]; then
    echo "⚠  readme.txt Stable tag is '$STABLE_TAG' but deploying '$VERSION'."
    echo "   WordPress.org serves whatever Stable tag points at — fix this first unless intentional."
    [[ "$ASSUME_YES" -eq 1 ]] || { read -r -p "   Continue anyway? [y/N] " a; [[ "$a" == "y" || "$a" == "Y" ]] || exit 1; }
fi

echo "→ Plugin source : $SRC"
echo "→ SVN working   : $SVN_WC"
echo "→ Version       : $VERSION"
echo

# ─── Checkout or update the SVN working copy ───────────────────────────────────
if [[ -d "${SVN_WC}/.svn" ]]; then
    echo "→ Updating existing SVN checkout…"
    svn update --username "$SVN_USER" "$SVN_WC"
else
    echo "→ Checking out SVN repo (first run)…"
    svn checkout --username "$SVN_USER" "$SVN_URL" "$SVN_WC"
fi

mkdir -p "${SVN_WC}/trunk" "${SVN_WC}/tags"

# ─── Refuse to overwrite an existing tag ───────────────────────────────────────
if svn ls "${SVN_URL}/tags/${VERSION}" --username "$SVN_USER" >/dev/null 2>&1; then
    echo "✗ Tag ${VERSION} already exists on the server. Bump the version first." >&2
    exit 1
fi

# ─── Sync source → trunk (delete removed files, keep .svn metadata) ────────────
echo "→ Syncing files into trunk…"
rsync -a --delete --exclude='.svn' "${SRC}/" "${SVN_WC}/trunk/"

# ─── Reconcile SVN adds and deletes ────────────────────────────────────────────
cd "$SVN_WC"
# Stage new files.
svn add --force trunk >/dev/null
# Remove files that rsync deleted but SVN still tracks (status "!" = missing).
MISSING="$(svn status trunk | awk '/^!/{print $2}')"
if [[ -n "$MISSING" ]]; then
    echo "→ Removing deleted files from SVN:"
    echo "$MISSING" | sed 's/^/   /'
    echo "$MISSING" | xargs -I{} svn rm "{}" >/dev/null
fi

# ─── Tag this release (copy trunk → tags/VERSION) ──────────────────────────────
echo "→ Tagging release ${VERSION}…"
svn copy trunk "tags/${VERSION}" >/dev/null

# ─── Show what will be committed ───────────────────────────────────────────────
echo
echo "──────── Pending SVN changes ────────"
svn status
echo "─────────────────────────────────────"
echo

# ─── Confirm + commit ──────────────────────────────────────────────────────────
if [[ "$ASSUME_YES" -ne 1 ]]; then
    read -r -p "Commit and publish ${VERSION} to WordPress.org? [y/N] " ans
    [[ "$ans" == "y" || "$ans" == "Y" ]] || { echo "Aborted — nothing committed."; exit 1; }
fi

svn commit --username "$SVN_USER" -m "Release ${VERSION}"
echo "✓ Published ${VERSION}. Live (after directory sync): https://wordpress.org/plugins/folio-gatehouse"
