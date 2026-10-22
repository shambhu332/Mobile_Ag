"""Synthetic installed-package snapshots; no ADB/device access."""
import pytest

from mobileag.dast.runtime_package_auditor import summarize_runtime_package


def test_snapshot_reports_permission_states_and_exact_manifest_delta_without_paths():
    info={
        'package_name':'org.example.fixture','version_name':'1.2','version_code':'12','target_sdk':'35',
        'requested_permissions':['android.permission.CAMERA','org.example.fixture.SPECIAL'],
        'granted_permissions':['android.permission.CAMERA','android.permission.READ_CONTACTS'],
        'data_dir':'/sensitive/data/path','code_path':'/sensitive/apk/path',
    }
    result=summarize_runtime_package('org.example.fixture',info,
        ['android.permission.CAMERA','android.permission.READ_SMS'])
    assert result['status']=='observed' and result['proof_status']=='not_proven'
    assert result['granted_requested_permissions']==['android.permission.CAMERA']
    assert result['requested_not_granted_permissions']==['org.example.fixture.SPECIAL']
    assert result['granted_not_requested_permissions']==['android.permission.READ_CONTACTS']
    assert result['static_comparison_status']=='different_review_required'
    assert result['static_delta']=={
        'runtime_only':['org.example.fixture.SPECIAL'],
        'static_only':['android.permission.READ_SMS'],
    }
    assert '/sensitive/' not in repr(result)


@pytest.mark.parametrize('info', [
    None,
    {'package_name':'org.example.other','requested_permissions':[],'granted_permissions':[]},
    {'package_name':'org.example.fixture','requested_permissions':['bad;id'],'granted_permissions':[]},
    {'package_name':'org.example.fixture','requested_permissions':[],'granted_permissions':['android.permission.'+'A'*600]},
    {'package_name':'org.example.fixture','requested_permissions':['android.permission.CAMERA']*513,'granted_permissions':[]},
])
def test_invalid_or_unbounded_package_snapshots_fail_closed(info):
    with pytest.raises(ValueError):
        summarize_runtime_package('org.example.fixture',info)
