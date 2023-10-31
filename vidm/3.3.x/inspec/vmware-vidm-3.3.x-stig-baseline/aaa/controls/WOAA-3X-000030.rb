control 'WOAA-3X-000030' do
  title 'Workspace ONE Access must be configured to enforce a minimum 15-character password length.'
  desc  'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc  'rationale', ''
  desc  'check', "
    Login to the Workspace ONE Access admin console at \"https://<hostname>/SAAS/admin\" using administrative credentials.

    Click the \"Users and Groups\" tab then \"Settings\" to view the password policies.

    If \"Minimum length for passwords\" is not set to at least \"15\", this is a finding.
  "
  desc 'fix', "
    Login to the Workspace ONE Access admin console at \"https://<hostname>/SAAS/admin\" using administrative credentials.

    Click the \"Users and Groups\" tab then \"Settings\".

    Set \"Minimum length for passwords\" to at least \"15\" and click Save.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000164-AAA-000450'
  tag gid: 'V-WOAA-3X-000030'
  tag rid: 'SV-WOAA-3X-000030'
  tag stig_id: 'WOAA-3X-000030'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']

  describe 'This control is a manual audit...skipping...' do
    skip 'This control is a manual audit...skipping...'
  end
end
