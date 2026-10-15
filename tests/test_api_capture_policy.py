from mobileag.web.policy import check_action


def test_api_capture_requires_enabled_action_and_explicit_network_scope():
    base = {'devices': [], 'packages': [], 'origins': [], 'methods': ['GET'],
            'actions': ['api_capture']}
    assert not check_action(base, 'api_capture', {})
    scoped = {**base, 'origins': ['https://api.example.test']}
    assert check_action(scoped, 'api_capture', {})
    assert not check_action({**scoped, 'actions': []}, 'api_capture', {})
