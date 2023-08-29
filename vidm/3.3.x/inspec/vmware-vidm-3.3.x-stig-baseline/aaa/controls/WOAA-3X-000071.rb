control 'WOAA-3X-000071' do
  title 'Workspace ONE Access must not provide environment information to third parties.'
  desc  'Providing technical details about an environments infrastructure to third parties could unknowningly expose sensitive information to bad actors if intercepted.'
  desc  'rationale', ''
  desc  'check', "
    Login to the Workspace ONE Access admin console at \"https://<hostname>/SAAS/admin\" using administrative credentials.

    Navigate to the \"Appliance Settings\" tab and select Telemetry.

    If the box is checked next to \"Join the VMware Customer Experience Improvement Program\", this is a finding.
  "
  desc 'fix', "
    Login to the Workspace ONE Access admin console at \"https://<hostname>/SAAS/admin\" using administrative credentials.

    Navigate to the \"Appliance Settings\" tab and select Telemetry.

    Uncheck the box next to \"Join the VMware Customer Experience Improvement Program\" and click Save.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AAA-000690'
  tag gid: 'V-WOAA-3X-000071'
  tag rid: 'SV-WOAA-3X-000071'
  tag stig_id: 'WOAA-3X-000071'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This control is a manual audit...skipping...' do
    skip 'This control is a manual audit...skipping...'
  end
end
