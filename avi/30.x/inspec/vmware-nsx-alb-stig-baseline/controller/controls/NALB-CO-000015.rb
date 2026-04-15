control 'NALB-CO-000015' do
  title 'The NSX Advanced Load Balancer Controller must protect against an individual (or process acting on behalf of an individual) falsely denying having performed organization-defined actions to be covered by non-repudiation.'
  desc  "
    This requirement supports non-repudiation of actions taken by an administrator and is required in order to maintain the integrity of the configuration management process. All configuration changes to the network device are logged, and administrators authenticate with two-factor authentication before gaining administrative access. Together, these processes will ensure the administrators can be held accountable for the configuration changes they implement.

    To meet this requirement, the network device must log administrator access and activity.
  "
  desc  'rationale', ''
  desc  'check', "
    Review access and authorization to verify a remote identity provider is used that enables multi-factor authentication to the controller.

    From the NSX ALB Controller web interface go to Administration >> System Settings >> Authentication.

    If the authentication type is not \"Remote\" and the identity source does not provide multi-factor authentication, this is a finding.
  "
  desc 'fix', "
    To configure remote authentication to an identity provider that enables multi-factor authentication, do the following:

    From the NSX ALB Controller web interface go to Administration >> System Settings.

    Click the edit icon next to \"System Settings\".

    Select the \"Remote\" radio button and add or create an \"Auth Profile\" and \"Mapping Profile\" then click Save.

    Note: The NSX ALB Controller supports LDAP, SAML, and TACACS_PLUS as a remote identity source.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000080-NDM-000220'
  tag satisfies: ['SRG-APP-000149-NDM-000247', 'SRG-APP-000516-NDM-000336']
  tag gid: 'V-NALB-CO-000015'
  tag rid: 'SV-NALB-CO-000015'
  tag stig_id: 'NALB-CO-000015'
  tag cci: ['CCI-000166', 'CCI-000370', 'CCI-000765']
  tag nist: ['AU-10', 'CM-6 (1)', 'IA-2 (1)']

  describe 'This check is a manual or policy based check and must be reviewed manually.' do
    skip 'Manually check if remote identity provider is used that enables multi-factor authentication to the controller'
  end
end
