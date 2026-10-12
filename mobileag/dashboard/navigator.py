"""Loopback-only deterministic dashboard navigation, not app/device automation."""
from urllib.parse import urlsplit

from mobileag.dashboard.client import DashboardClient, DashboardError, safe_endpoint

VIEWS = ('overview', 'assessment', 'surface', 'findings', 'scans', 'settings',
         'dast', 'taint', 'api', 'automation', 'agents')


def permitted_request(origin, url, method):
    try:
        parsed, base = urlsplit(url), urlsplit(origin)
    except ValueError:
        return False
    if method != 'GET' or (parsed.scheme, parsed.netloc) != (base.scheme, base.netloc):
        return False
    if parsed.path == '/' and not parsed.query and not parsed.fragment:
        return True
    if parsed.path.startswith('/static/'):
        return not parsed.query and '%' not in parsed.path and '..' not in parsed.path and '\\' not in parsed.path
    return safe_endpoint(parsed.path + ('?' + parsed.query if parsed.query else ''))


def read_only_route(origin, blocked, route):
    """Fetch once without redirects, so a browser cannot follow a redirect chain.

    Route interception alone is insufficient for a redirect chain. Fulfill only
    non-redirect responses; block redirects before returning them to the page.
    """
    request = route.request
    if not permitted_request(origin, request.url, request.method):
        blocked.append({'kind': 'request', 'method': request.method})
        route.abort()
        return
    response = route.fetch(max_redirects=0, timeout=10000)
    if 300 <= response.status < 400:
        blocked.append({'kind': 'redirect', 'method': request.method})
        route.abort()
    else:
        route.fulfill(response=response)
    response.dispose()


def navigate(client: DashboardClient, views=VIEWS, chromium=None, headed=False):
    """Connect through the real form, visit exact sections, close the session.

    No browser profile, trace, storage-state file, screenshot or DOM dump is
    retained. Only bounded section/status metadata is returned. Any write or
    external request is blocked before transmission. WebSockets are disabled.
    """
    if not views or any(view not in VIEWS for view in views) or len(views) > len(VIEWS):
        raise DashboardError('Choose known dashboard sections within the navigation budget')
    client.get('/api/status')  # Fail before browser work on stale/wrong credentials.
    try:
        from playwright.sync_api import sync_playwright, Error as BrowserError
    except ImportError:
        raise DashboardError('Install the dashboard browser extra and a Chromium browser') from None
    blocked = []
    page_errors = []
    visited = []
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(executable_path=chromium, headless=not headed)
            context = browser.new_context(service_workers='block', accept_downloads=False)
            try:
                context.route('**/*', lambda route: read_only_route(client.origin, blocked, route))
                # Routed sockets never connect to a real server unless explicitly
                # connected by the handler. Leave them inert; sync close callbacks
                # can deadlock on the validated Python 3.14 browser stack.
                context.route_web_socket('**/*', lambda socket: None)
                page = context.new_page()
                page.on('pageerror', lambda error: page_errors.append('dashboard_page_error'))
                page.goto(client.origin, wait_until='domcontentloaded', timeout=30000)
                page.locator('#session-token').fill(client._token)
                page.locator('#session-token').press('Enter')
                page.locator('#session-connect').wait_for(state='hidden', timeout=15000)
                for view in views:
                    # Navigation-only buttons, never heuristic text/control clicks.
                    details = page.locator('#advanced-tools')
                    if details.count():
                        details.evaluate('(element) => element.open = true')
                    page.locator('#nav-' + view).click(timeout=10000)
                    panel = page.locator('#view-' + view)
                    panel.wait_for(state='visible', timeout=10000)
                    visited.append({'view': view, 'visible': True})
                label = page.locator('#sidebar-ws-status')
                if label.count():
                    label.evaluate("element => element.textContent = 'Disabled in read-only navigator'")
                if page.locator('#session-connect').is_visible():
                    raise DashboardError('Dashboard session expired during navigation')
            finally:
                context.close()
                browser.close()
    except DashboardError:
        raise
    except BrowserError:
        raise DashboardError('Browser connection/navigation failed; no credentials or raw browser error retained') from None
    return {'connected': True, 'visited': visited, 'blocked_requests': blocked,
            'page_errors': page_errors, 'writes_authorized': False,
            'device_actions_authorized': False, 'session_persisted': False,
            'telemetry': 'disabled_in_read_only_navigation'}
