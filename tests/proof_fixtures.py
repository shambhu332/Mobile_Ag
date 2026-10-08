"""Synthetic attestations test field/binding rules, not a real exploit."""
def confirmation_evidence(package='org.example.synthetic',version='1.0',digest='a'*64):
    return {'artifact_sha256':digest,'package_name':package,'app_version':version,
        'os_build':'synthetic-test-build','attacker_context':'ordinary_app',
        'entry_point':'Synthetic exported test entry','attacker_control':'Synthetic marker controlled by test fixture',
        'sensitive_sink':'Synthetic guarded fixture operation','security_boundary':'Synthetic caller isolation fixture',
        'observed_impact':'Synthetic marker reached fixture output',
        'reproduction_steps':['Install researcher-controlled fixture','Send synthetic marker and record fixture output'],
        'positive_control':'Fixture accepts the authorized synthetic marker','negative_control':'Denied marker does not reach fixture output',
        'evidence_refs':['synthetic-fixture:positive','synthetic-fixture:negative'],
        'unprivileged_attacker_confirmed':True,'unmodified_authorization_confirmed':True,
        'synthetic_data_confirmed':True,'scope_confirmed':True}
