control 'WOAA-3X-000009' do
  title 'Workspace ONE Access must be configured to automatically lock user accounts after three consecutive invalid logon attempts within a 15-minute time period.'
  desc  'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account.'
  desc  'rationale', ''
  desc  'check', "
    Login to the Workspace ONE Access admin console at \"https://<hostname>/SAAS/admin\" using administrative credentials.

    Click the \"Users and Groups\" tab. Click on \"Settings\", in the top right.

    If \"Failed password attempts\" is not \"3\", this is a finding.

    If \"Failed authentication attempts interval\" is not set to \"15\" minutes, this is a finding.
  "
  desc 'fix', "
    Login to the Workspace ONE Access admin console at \"https://<hostname>/SAAS/admin\" using administrative credentials.

    Click the \"Users and Groups\" tab. Click on \"Settings\", in the top right.

    Set \"Failed password attempts\" to \"3\".

    Set \"Failed authentication attempts interval\" to \"15\" minutes.

    Click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000065-AAA-000200'
  tag gid: 'V-WOAA-3X-000009'
  tag rid: 'SV-WOAA-3X-000009'
  tag stig_id: 'WOAA-3X-000009'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']

  describe 'This control is a manual audit...skipping...' do
    skip 'This control is a manual audit...skipping...'
  end
end
