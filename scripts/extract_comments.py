#!/usr/bin/env python3
"""Render issue comments from isite output into a sanitized JSON data file.

isite v0.2.2 writes each comment body as *raw Markdown* into the post front
matter, under ``[extra.comments].content``. Outputting that with Zola's
``| safe`` would be an XSS hole, so this script:

1. reads ``output/content/issue-*.md`` (offline; no network, no credentials),
2. renders each ``content`` from Markdown,
3. sanitizes the resulting HTML with a strict allowlist (nh3/ammonia),
4. writes ``comments.json`` keyed by page slug (e.g. ``issue-26``),
5. removes ``extra.comments`` from the post front matter and rewrites it,
6. keeps only comments the repository owner approved (see below).

Comment bodies are truncated to ``MAX_COMMENT_CHARS`` for display. GitHub has
no such limit, so this is a display cap, not a submission cap; the template
links the full comment on GitHub when truncation happened.

Approval: anyone can comment on a public issue, so a comment is only rendered
once the owner reacts to it with 👍 (+1) or ❤️ (heart) *after its last edit*.
Reactions are not part of isite's output, so ``scripts/approve_comments.py``
collects the approved IDs into a JSON file; this script reads that file as its
third argument (or ``APPROVED_COMMENTS_JSON``). Without it no comment is
rendered.

Step 5 matters: untrusted comment text must not stay in the TOML front matter
that Zola parses. The splitter tolerates ``+++`` lines and control characters
inside comments, but comment text is only ever rendered through the sanitizer.
After this script, Zola only sees trusted front matter; comment HTML lives in
``comments.json`` and has already been sanitized.

The template renders only the sanitized ``html`` field. If a comment trips the
post-sanitize audit, the build fails instead of publishing it.

Run this once on freshly generated isite output: step 5 rewrites the content
files, so re-running on the same directory would find no comments left.

Usage: extract_comments.py [CONTENT_DIR] [OUTPUT_JSON] [APPROVED_JSON]
"""

from __future__ import annotations

import json
import os
import re
import sys
import tomllib
from html.parser import HTMLParser
from pathlib import Path

import nh3
import tomli_w
from marko.ext.gfm import gfm as markdown

# Deliberately small allowlist: comments are untrusted input.
ALLOWED_TAGS = {
    "a",
    "blockquote",
    "br",
    "code",
    "del",
    "details",
    "em",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "hr",
    "img",
    "li",
    "ol",
    "p",
    "pre",
    "s",
    "span",
    "strong",
    "sub",
    "summary",
    "sup",
    "table",
    "tbody",
    "td",
    "th",
    "thead",
    "tr",
    "ul",
}
ALLOWED_ATTRIBUTES = {
    "a": {"href", "title"},
    "img": {"alt", "src", "title"},
    "ol": {"start"},
}
# Force safe defaults on images embedded in comments.
SET_ATTRIBUTES = {
    "img": {"loading": "lazy", "referrerpolicy": "no-referrer"},
}
ALLOWED_URL_SCHEMES = {"http", "https", "mailto"}

# isite writes comment bodies as TOML literal strings; a raw C0 control
# character (or a bare CR) makes that string invalid TOML, which would block
# every later deploy. Strip them before parsing: they carry no meaning in a
# comment and are not allowed in TOML literal strings.
CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
COMMENT_ID_RE = re.compile(r"#issuecomment-(\d+)$")

GITHUB_URL_PREFIX = "https://github.com/"
AVATAR_URL_PREFIX = "https://avatars.githubusercontent.com/"

# Defense in depth: these must never survive sanitization.
FORBIDDEN_TAGS = {
    "base",
    "embed",
    "form",
    "iframe",
    "link",
    "math",
    "meta",
    "object",
    "script",
    "style",
    "svg",
    "template",
}
FORBIDDEN_ATTRIBUTES = {"srcdoc", "style"}
DANGEROUS_SCHEME_RE = re.compile(
    r"^(?:javascript|vbscript|data):", re.IGNORECASE
)
MAX_COMMENT_HTML_BYTES = 256 * 1024
# Display limit for a comment. Keep in sync with the hint in config.toml.
MAX_COMMENT_CHARS = 140
OVERSIZED_COMMENT_HTML = "<p>这条评论内容过长，未在页面上展开，请到对应的 GitHub Issue 查看。</p>"


def render_comment(body: str) -> str:
    """Render Markdown and return allowlist-sanitized HTML."""
    rendered = markdown.convert(body)
    html = nh3.clean(
        rendered,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        url_schemes=ALLOWED_URL_SCHEMES,
        link_rel="noopener noreferrer nofollow",
        set_tag_attribute_values=SET_ATTRIBUTES,
        strip_comments=True,
    )
    # Degrade instead of failing the whole deploy if someone posts an
    # extremely long comment (availability, not XSS).
    if len(html.encode("utf-8")) > MAX_COMMENT_HTML_BYTES:
        return OVERSIZED_COMMENT_HTML
    return html


class _AuditParser(HTMLParser):
    """Parse sanitized HTML and report dangerous tags/attributes/schemes."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.problem: str | None = None

    def _check(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag in FORBIDDEN_TAGS:
            self.problem = f"forbidden tag <{tag}>"
            return
        for name, value in attrs:
            name = name.lower()
            if name.startswith("on") or name in FORBIDDEN_ATTRIBUTES:
                self.problem = f"forbidden attribute {name!r} on <{tag}>"
                return
            if name in {"href", "src"} and value is not None:
                # Browsers ignore ASCII control characters in URL schemes
                # (e.g. "java\nscript:"), so strip them before checking.
                normalized = re.sub(r"[\x00-\x20\x7f]", "", value)
                if DANGEROUS_SCHEME_RE.match(normalized):
                    self.problem = f"forbidden URL scheme in {name!r} on <{tag}>"
                    return

    def handle_starttag(  # type: ignore[override]
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        self._check(tag, attrs)

    def handle_startendtag(  # type: ignore[override]
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        self._check(tag, attrs)


def audit_html(html: str, where: str) -> None:
    """Fail closed if anything dangerous survived sanitization."""
    parser = _AuditParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception as exc:  # noqa: BLE001 - malformed output is a hard failure
        raise SystemExit(f"error: {where}: unable to audit comment HTML: {exc}") from exc
    if parser.problem:
        raise SystemExit(
            f"error: {where}: sanitizer left {parser.problem}; refusing to build"
        )


def normalize_text(text: str) -> str:
    """Make isite output parseable even if a comment contains raw controls."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return CONTROL_CHARS_RE.sub("", text)


def split_front_matter(path: Path) -> tuple[str, str]:
    """Split TOML front matter without trusting user-controlled text.

    isite embeds raw comment bodies as TOML multi-line strings and writes a
    leading newline before the opening ``+++``. A ``+++`` line inside such a
    string must not be mistaken for the front matter terminator, so candidates
    are accepted only when the TOML prefix parses.

    A false positive (``+++`` inside a comment) makes the prefix unparseable.
    Retry from one character after it while keeping the candidate start
    fixed: starting the next candidate *after* the ``+++`` would drop the
    front matter prefix, so the real terminator could never parse.
    """
    text = normalize_text(path.read_text(encoding="utf-8"))
    opening = re.match(r"[ \t\r\n]*\+\+\+\n", text)
    if not opening:
        raise SystemExit(f"error: {path}: missing TOML front matter")

    start = opening.end()
    search_from = start
    while True:
        end = text.find("\n+++\n", search_from)
        if end == -1:
            raise SystemExit(f"error: {path}: unterminated TOML front matter")
        candidate = text[start:end]
        try:
            tomllib.loads(candidate)
        except tomllib.TOMLDecodeError:
            search_from = end + 1
            continue
        return candidate, text[end + 5 :]


def safe_url(value: object, prefix: str) -> str:
    url = str(value or "")
    return url if url.startswith(prefix) else ""


def comment_id(url: str) -> int:
    """Extract the numeric id from a comment permalink."""
    match = COMMENT_ID_RE.search(url)
    if match is None:
        raise SystemExit(f"error: cannot determine comment id from {url!r}")
    return int(match.group(1))


def load_approved_comments(path: Path | None) -> set[int]:
    """Load the owner-approved comment ids; a missing list hides everything."""
    if path is None:
        print(
            "warning: no approval list given; hiding every comment "
            "(pass APPROVED_JSON or set APPROVED_COMMENTS_JSON)",
            file=sys.stderr,
        )
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SystemExit(f"error: approval list not found: {path}") from None
    except json.JSONDecodeError as exc:
        raise SystemExit(f"error: invalid approval list {path}: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("approved"), list):
        raise SystemExit(f'error: {path}: expected {{"approved": [...]}}')
    approved: set[int] = set()
    for value in data["approved"]:
        if not isinstance(value, int) or isinstance(value, bool):
            raise SystemExit(f"error: {path}: non-integer comment id {value!r}")
        approved.add(value)
    return approved


def extract_post(
    path: Path, approved: set[int]
) -> tuple[str, list[dict[str, str | bool]], int]:
    front_matter, body = split_front_matter(path)
    try:
        data = tomllib.loads(front_matter)
    except tomllib.TOMLDecodeError as exc:
        raise SystemExit(f"error: {path}: invalid TOML front matter: {exc}") from exc

    extra = data.get("extra", {})
    if not isinstance(extra, dict):
        raise SystemExit(f"error: {path}: extra is not a table")
    raw_comments = extra.pop("comments", [])
    if not isinstance(raw_comments, list):
        raise SystemExit(f"error: {path}: extra.comments is not a list")

    comments: list[dict[str, str | bool]] = []
    for index, comment in enumerate(raw_comments, start=1):
        if not isinstance(comment, dict):
            raise SystemExit(f"error: {path}: comment #{index} is not a table")
        where = f"{path.name} comment #{index}"
        if comment_id(str(comment.get("url") or "")) not in approved:
            # Not approved by the owner: keep the text out of the rendered
            # page entirely (it is still removed from the front matter below).
            continue
        raw_body = str(comment.get("content") or "")
        visible_text = raw_body.strip()
        truncated = len(visible_text) > MAX_COMMENT_CHARS
        if truncated:
            raw_body = visible_text[:MAX_COMMENT_CHARS].rstrip()
        html = render_comment(raw_body)
        audit_html(html, where)
        comments.append(
            {
                "author_name": str(comment.get("author_name") or "")[:100],
                "author_avatar": safe_url(
                    comment.get("author_avatar"), AVATAR_URL_PREFIX
                ),
                "url": safe_url(comment.get("url"), GITHUB_URL_PREFIX),
                "updated_at": str(comment.get("updated_at") or "")[:32],
                "truncated": truncated,
                "html": html,
            }
        )

    # Drop untrusted comment bodies from the front matter that Zola will parse.
    if raw_comments:
        path.write_text(
            "+++\n" + tomli_w.dumps(data) + "+++\n" + body,
            encoding="utf-8",
        )
    return path.stem, comments, len(raw_comments)


def main(argv: list[str]) -> int:
    content_dir = Path(argv[1] if len(argv) > 1 else "output/content")
    output_path = Path(argv[2] if len(argv) > 2 else content_dir.parent / "comments.json")
    approvals_path = Path(argv[3]) if len(argv) > 3 else None
    if approvals_path is None and os.environ.get("APPROVED_COMMENTS_JSON"):
        approvals_path = Path(os.environ["APPROVED_COMMENTS_JSON"])
    approved = load_approved_comments(approvals_path)

    if not content_dir.is_dir():
        raise SystemExit(f"error: content directory not found: {content_dir}")

    pages: dict[str, list[dict[str, str | bool]]] = {}
    total_comments = 0
    hidden_comments = 0
    for path in sorted(content_dir.glob("issue-*.md")):
        slug, comments, raw_total = extract_post(path, approved)
        pages[slug] = comments
        total_comments += len(comments)
        hidden_comments += raw_total - len(comments)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(
            pages, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        + "\n",
        encoding="utf-8",
    )
    print(
        f"comments: rendered {total_comments} approved comment(s) "
        f"for {len(pages)} post(s), hid {hidden_comments} unapproved "
        f"-> {output_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
