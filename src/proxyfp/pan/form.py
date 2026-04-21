"""Selector layer for Palo Alto's URL categorization "Request Change" form.

This is the churn surface: PAN updates their UI without notice. Keep logic
minimal here; every selector is a single constant so patching is one-line when
something breaks.

The change form is a custom Fuel UX pillbox, not a native <select>. The flow:
  1. Click #add_category_btn to open the dropdown.
  2. (optional) Type in #searchInput to filter.
  3. Click li.enable[cateIndex='<id>'] inside #cate_list.
  4. The pillbox stores selections; on submit a JS handler writes the id list
     to the hidden #id_new_category input.
"""

from __future__ import annotations

from dataclasses import dataclass

PORTAL_URL = "https://urlfiltering.paloaltonetworks.com/"
PROXY_CATEGORY_NAME = "Proxy-Avoidance-and-Anonymizers"
PROXY_CATEGORY_ID = "58"


@dataclass(frozen=True)
class Selectors:
    url_input: str = "#id_url"
    url_submit: str = "form[action='/query/'] button[type='submit']"
    request_change_button: str = "a:has-text('Request Change'), button:has-text('Request Change'), a:has-text('Request a Change'), button:has-text('Change Request')"
    add_category_btn: str = "#add_category_btn"
    category_search_input: str = "#dropdown #searchInput"
    category_list_item: str = "#cate_list li.enable[cateIndex='{id}']"
    category_pill: str = "#cate_pillbox .pill:has-text('{name}')"
    comment_textarea: str = "#id_comment"
    form_submit: str = "#cr_form input[type='submit'][value='Submit']"
    confirmation_locator: str = "text=/thank you|submitted|received|ticket|your request/i"
    login_indicator: str = "input[name='email'], input[type='password'], a[href*='/login'], text=/sign in|log in to/i"
    logged_in_indicator: str = "a[href='/logout/'], a[href*='/logout']"


SELECTORS = Selectors()
