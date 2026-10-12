"""Dashboard CLI: private connection, read-only HTTP/curl and UI navigation."""
import json
import os

import click

from mobileag.dashboard.client import DashboardClient, DashboardError
from mobileag.dashboard.navigator import VIEWS, navigate


def connection(url):
    token = os.environ.get('MOBILEAG_API_TOKEN')
    if not token:
        token = click.prompt('Dashboard session token', hide_input=True, type=str)
    return DashboardClient(url, token)


@click.group()
def dashboard():
    """Connect to and navigate your local dashboard; never auto-start tests."""


@dashboard.command('api')
@click.option('--url', default='http://127.0.0.1:8080', show_default=True)
@click.option('--path', default='/api/status', show_default=True)
@click.option('--transport', type=click.Choice(['httpx', 'curl']), default='httpx')
def api(url, path, transport):
    """Read an allowlisted endpoint with an ephemeral session token."""
    try:
        result = connection(url).get(path, transport)
    except DashboardError as error:
        raise click.ClickException(str(error)) from None
    click.echo(json.dumps(result, indent=2))


@dashboard.command('navigate')
@click.option('--url', default='http://127.0.0.1:8080', show_default=True)
@click.option('--view', type=click.Choice(VIEWS), multiple=True, help='Repeat for a workflow; defaults to all sections.')
@click.option('--chromium', type=click.Path(exists=True, dir_okay=False), help='Optional installed Chromium executable.')
@click.option('--headed', is_flag=True, help='Show the temporary browser; session closes when navigation ends.')
def ui_navigation(url, view, chromium, headed):
    """Self-connect through the real login form, then visit dashboard sections."""
    try:
        result = navigate(connection(url), view or VIEWS, chromium, headed)
    except DashboardError as error:
        raise click.ClickException(str(error)) from None
    click.echo(json.dumps(result, indent=2))
    if result['page_errors'] or result['blocked_requests']:
        raise click.ClickException('Navigation recorded blocked requests or page errors; inspect the bounded result')
