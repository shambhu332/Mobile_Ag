"""Real-form self-connect/navigation and curl against a synthetic local server."""
import argparse
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from mobileag.dashboard.client import DashboardClient, DashboardError
from mobileag.dashboard.navigator import navigate
from browser_console_regression import existing_fixture, isolated_environment, start_ready


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--chromium', required=True)
    args = parser.parse_args()
    server_source, _ = existing_fixture()
    with tempfile.TemporaryDirectory(prefix='mobileag-self-navigation-') as temporary:
        root = Path(temporary)
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0)); port = listener.getsockname()[1]
        runner = root/'runner.py'; runner.write_text(server_source)
        # Fixture logs contain synthetic data only and disappear with the lab.
        with (root/'server.log').open('w') as log:
            server = subprocess.Popen([sys.executable, str(runner)], cwd=root,
                env=isolated_environment(root, port), stdout=log, stderr=log)
            try:
                origin = f'http://127.0.0.1:{port}'
                start_ready(server, origin)
                client = DashboardClient(origin, 'synthetic-local-only')
                assert client.get('/api/status')['status_code'] == 200
                assert client.get('/api/status', 'curl')['status_code'] == 200
                try:
                    DashboardClient(origin, 'synthetic-wrong-token').get()
                except DashboardError:
                    pass
                else:
                    raise AssertionError('Invalid token accepted')
                before_sockets = client.get('/api/status')['data']['websocket_subscribers']
                before_assessments = client.get('/api/assessments')['data']
                before_runs = client.get('/api/automation/runs')['data']
                result = navigate(client, chromium=args.chromium)
                assert len(result['visited']) == 11
                assert not result['blocked_requests'], result
                assert not result['page_errors'], result
                assert not result['session_persisted']
                assert client.get('/api/status')['data']['websocket_subscribers'] == before_sockets
                # Nothing was started by connecting/navigating.
                assert client.get('/api/assessments')['data'] == before_assessments
                assert client.get('/api/automation/runs')['data'] == before_runs
                print(json.dumps({'status': 'passed', 'scope': 'synthetic loopback only',
                    'self_login': 'real token form', 'curl': 'authenticated GET',
                    'navigation': result, 'jobs_started': 0}))
            finally:
                server.terminate()
                try: server.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    server.kill(); server.wait(timeout=5)


if __name__ == '__main__':
    main()
