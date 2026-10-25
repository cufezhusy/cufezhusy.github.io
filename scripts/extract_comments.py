#!/usr/bin/env python3
"""Render issue comments from isite output into a sanitized JSON data file.

isite v0.2.2 writes each comment body as *raw Markdown* into the post front
matter, under ``[extra.comments].content``. Outputting that with Zola's
``| safe`` would be an XSS hole, so this script:

1. reads ``output/content/issue-*.md`` (offline; no network, no credentials),
2. renders each ``content`` from Markdown,
3. sanitizes the resulting HTML with a strict allowlist (nh3/ammonia),
4. writes ``comments.json`` keyed by page slug (e.g. ``issue-26``),
5. removes ``extra.comments`` from the post front matter and rewrites it.

Comment bodies are truncated to ``MAX_COMMENT_CHARS`` for display. GitHub has
no such limit, so this is a display cap, not a submission cap; the template
links the full comment on GitHub when truncation happened.

Step 5 matters: untrusted comment text must not stay in the TOML front matter,
otherwise a comment containing a ``+++`` line could confuse front matter
splitting. After this script, Zola only ever sees trusted front matter; comment
HTML lives in ``comments.json`` and has already been sanitized.

The template renders only the sanitized ``html`` field. If a comment trips the
post-sanitize audit, the build fails instead of publishing it.

Run this once on freshly generated isite output: step 5 rewrites the content
files, so re-running on the same directory would find no comments left.

Usage: extract_comments.py [CONTENT_DIR] [OUTPUT_JSON]
"""

from __future__ import annotations

import json
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


def split_front_matter(path: Path) -> tuple[str, str]:
    """Split TOML front matter without trusting user-controlled text.

    isite embeds raw comment bodies as TOML multi-line strings. A ``+++`` line
    inside such a string must not be mistaken for the front matter terminator,
    so candidates are accepted only when the TOML prefix parses.
    """
    text = path.read_text(encoding="utf-8")
    if not text.startswith("+++\n"):
        raise SystemExit(f"error: {path}: missing TOML front matter")

    search_from = 4
    while True:
        end = text.find("\n+++\n", search_from)
        if end == -1:
            raise SystemExit(f"error: {path}: unterminated TOML front matter")
        candidate = text[4:end]
        try:
            tomllib.loads(candidate)
        except tomllib.TOMLDecodeError:
            search_from = end + 5
            continue
        return candidate, text[end + 5 :]


def safe_url(value: object, prefix: str) -> str:
    url = str(value or "")
    return url if url.startswith(prefix) else ""


def extract_post(path: Path) -> tuple[str, list[dict[str, str | bool]]]:
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
    return path.stem, comments


def main(argv: list[str]) -> int:
    content_dir = Path(argv[1] if len(argv) > 1 else "output/content")
    output_path = Path(argv[2] if len(argv) > 2 else content_dir.parent / "comments.json")

    if not content_dir.is_dir():
        raise SystemExit(f"error: content directory not found: {content_dir}")

    pages: dict[str, list[dict[str, str | bool]]] = {}
    total_comments = 0
    for path in sorted(content_dir.glob("issue-*.md")):
        slug, comments = extract_post(path)
        pages[slug] = comments
        total_comments += len(comments)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(
            pages, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        + "\n",
        encoding="utf-8",
    )
    print(
        f"comments: rendered {total_comments} comment(s) "
        f"for {len(pages)} post(s) -> {output_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
