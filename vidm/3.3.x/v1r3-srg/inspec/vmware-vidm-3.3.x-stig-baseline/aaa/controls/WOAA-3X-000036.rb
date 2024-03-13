control 'WOAA-3X-000036' do
  title 'Workspace ONE Access must be configured to require the change of at least eight of the total number of characters when passwords are changed.'
  desc  'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Use of a complex password helps to increase the time and resources required to compromise the password. The more complex the password is, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc  'rationale', ''
  desc  'check', "
    Login to the Workspace ONE Access admin console at \"https://<hostname>/SAAS/admin\" using administrative credentials.

    Click the \"Users and Groups\" tab then \"Settings\" to view the password policies.

    If \"Number of characters from previous password allowed\" is not set to at least \"8\", this is a finding.
  "
  desc 'fix', "
    Login to the Workspace ONE Access admin console at \"https://<hostname>/SAAS/admin\" using administrative credentials.

    Click the \"Users and Groups\" tab then \"Settings\".

    Set \"Number of characters from previous password allowed\" to \"8\" and click Save.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000170-AAA-000500'
  tag gid: 'V-WOAA-3X-000036'
  tag rid: 'SV-WOAA-3X-000036'
  tag stig_id: 'WOAA-3X-000036'
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']

  describe 'This control is a manual audit...skipping...' do
    skip 'This control is a manual audit...skipping...'
  end
end
