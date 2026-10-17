"""Local API CLI: private connection and bounded read-only HTTP/curl."""
import json
import os

import click

from mobileag.dashboard.client import DashboardClient, DashboardError


def connection(url):
    token = os.environ.get('MOBILEAG_API_TOKEN')
    if not token:
        token = click.prompt('API bearer token', hide_input=True, type=str)
    return DashboardClient(url, token)


@click.group()
def dashboard():
    """Connect to the local API; never auto-start tests."""


@dashboard.command('api')
@click.option('--url', default='http://127.0.0.1:8080', show_default=True)
@click.option('--path', default='/api/status', show_default=True)
@click.option('--transport', type=click.Choice(['httpx', 'curl']), default='httpx')
def api(url, path, transport):
    """Read an allowlisted endpoint with an bearer token."""
    try:
        result = connection(url).get(path, transport)
    except DashboardError as error:
        raise click.ClickException(str(error)) from None
    click.echo(json.dumps(result, indent=2))
