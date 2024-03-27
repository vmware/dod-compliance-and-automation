control 'WOAA-3X-000067' do
  title 'Workspace ONE Access must be configured to use a unique shared secret when configuring the RADIUS authentication adapter.'
  desc  'Using standardized authentication protocols such as RADIUS, TACACS+, and Kerberos, an authentication server provides centralized and robust authentication services for the management of network components. An authentication server is very scalable as it supports many user accounts and authentication sessions with the network components.'
  desc  'rationale', ''
  desc  'check', "
    If the RADIUS adapter is not configured on any connectors, this is Not Applicable.

    Login to the Workspace ONE Access admin console at \"https://<hostname>/SAAS/admin\" using administrative credentials.

    On the VMware Identity Manager console Identity & Access Management tab, select Setup.

    On the Connectors page, select the Worker link for the connector being checked.

    Click Auth Adapters and then Radius Adapter.

    If the shared secret is not unique, this is a finding.
  "
  desc 'fix', "
    Login to the Workspace ONE Access admin console at \"https://<hostname>/SAAS/admin\" using administrative credentials.

    On the VMware Identity Manager console Identity & Access Management tab, select Setup.

    On the Connectors page, select the Worker link for the connector tp be configured.

    Click Auth Adapters and then Radius Adapter.

    Enter a unique shared secret and click Save.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AAA-000640'
  tag gid: 'V-WOAA-3X-000067'
  tag rid: 'SV-WOAA-3X-000067'
  tag stig_id: 'WOAA-3X-000067'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This control is a manual audit...skipping...' do
    skip 'This control is a manual audit...skipping...'
  end
end
