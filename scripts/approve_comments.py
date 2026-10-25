#!/usr/bin/env python3
"""Collect the issue comments the repository owner approved.

The blog renders comments statically, so without a gate anyone with a GitHub
account could put text and links on the site. A comment is therefore only
rendered after the owner reacts to it with 👍 (+1) or ❤️ (heart). The reaction
must be newer than the comment's last edit: if an approved comment is edited
later it disappears until the owner removes and re-adds the reaction, so a
benign comment cannot be approved and then edited into spam.

Reactions are not part of isite's output, so this script asks the GitHub API
and writes the approved comment IDs for ``extract_comments.py``. It needs a
token with ``issues: read`` only, and it never executes comment text.

Usage:
    approve_comments.py OUTPUT_JSON

Environment:
    GH_TOKEN / GITHUB_TOKEN   API token
    REPO                      "owner/name" (default: GITHUB_REPOSITORY)
    REPO_OWNER                owner login (default: GITHUB_REPOSITORY_OWNER)
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

API = "https://api.github.com"
PER_PAGE = 100
# Reactions that count as approval: thumbs up or heart.
APPROVAL_REACTIONS = {"+1", "heart"}
TIMEOUT_SECONDS = 30


def _token() -> str:
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""
    if not token:
        raise SystemExit("error: GH_TOKEN is not set")
    return token


def _get_json(url: str, token: str):
    request = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "cufezhusy-blog-comment-approval",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        detail = exc.read(200).decode("utf-8", "replace")
        raise SystemExit(f"error: GitHub API {exc.code} for {url}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise SystemExit(f"error: cannot reach the GitHub API: {exc}") from exc


def _iter_pages(url: str, token: str):
    page = 1
    while True:
        separator = "&" if "?" in url else "?"
        batch = _get_json(f"{url}{separator}per_page={PER_PAGE}&page={page}", token)
        if not isinstance(batch, list):
            raise SystemExit(f"error: unexpected API response for {url}")
        if not batch:
            return
        yield from batch
        if len(batch) < PER_PAGE:
            return
        page += 1


def _timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        raise SystemExit("usage: approve_comments.py OUTPUT_JSON")
    output_path = Path(argv[1])

    repo = os.environ.get("REPO") or os.environ.get("GITHUB_REPOSITORY") or ""
    owner = (
        os.environ.get("REPO_OWNER")
        or os.environ.get("GITHUB_REPOSITORY_OWNER")
        or ""
    )
    if "/" not in repo:
        raise SystemExit("error: REPO must look like 'owner/name'")
    if not owner:
        owner = repo.split("/", 1)[0]
    token = _token()

    approved: set[int] = set()
    checked = 0
    for comment in _iter_pages(f"{API}/repos/{repo}/issues/comments", token):
        checked += 1
        comment_id = comment.get("id")
        reactions = comment.get("reactions")
        if not isinstance(comment_id, int) or not isinstance(reactions, dict):
            continue
        if reactions.get("total_count", 0) <= 0:
            continue
        updated_at = _timestamp(comment.get("updated_at"))
        if updated_at is None:
            continue
        reactions_url = f"{API}/repos/{repo}/issues/comments/{comment_id}/reactions"
        for reaction in _iter_pages(reactions_url, token):
            if reaction.get("content") not in APPROVAL_REACTIONS:
                continue
            if (reaction.get("user") or {}).get("login") != owner:
                continue
            created_at = _timestamp(reaction.get("created_at"))
            if created_at is not None and created_at >= updated_at:
                approved.add(comment_id)
                break

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(
            {"approved": sorted(approved), "checked": checked},
            ensure_ascii=False,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"approve: {len(approved)} approved of {checked} comment(s) -> {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
