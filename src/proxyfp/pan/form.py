"""Selector layer for Palo Alto's URL categorization "Request Change" form.

This is the churn surface — PAN updates their UI without notice. Keep logic
minimal here; every selector is a single constant so patching is one-line when
something breaks.

The expected flow (as of plan authoring):
  1. Open https://urlfiltering.paloaltonetworks.com/
  2. Fill the URL lookup input, submit.
  3. Click "Request Change" / "Change Request" button.
  4. In the change form:
       - Set category to "proxy-avoidance-and-anonymizers".
       - Fill comment / justification textarea.
       - Submit (unless dry-run).
  5. Capture confirmation text / ticket id.

These selectors MUST be verified on first headed run with `page.pause()`.
If a selector below is wrong the submission will fail loudly — see submit.py.
"""

from __future__ import annotations

from dataclasses import dataclass

PORTAL_URL = "https://urlfiltering.paloaltonetworks.com/"
PROXY_CATEGORY = "proxy-avoidance-and-anonymizers"


@dataclass(frozen=True)
class Selectors:
    url_input: str = "input[name='url'], input[type='search'], input[placeholder*='URL' i]"
    url_submit: str = "button:has-text('Search'), button[type='submit']"
    request_change_button: str = "a:has-text('Request Change'), button:has-text('Request Change')"
    category_select: str = "select[name*='category' i], [data-testid*='category']"
    comment_textarea: str = "textarea[name*='comment' i], textarea[name*='justification' i], textarea"
    form_submit: str = "button:has-text('Submit'):not(:has-text('Back'))"
    confirmation_locator: str = "text=/thank you|submitted|received|ticket/i"
    login_indicator: str = "input[name='email'], input[type='password'], text=/sign in|log in/i"


SELECTORS = Selectors()
