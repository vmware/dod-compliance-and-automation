control 'WOAA-3X-000033' do
  title 'Workspace ONE Access must be configured to enforce password complexity by requiring that at least one lower-case character be used.'
  desc  'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Use of a complex password helps to increase the time and resources required to compromise the password. The more complex the password is, the greater the number of possible combinations that need to be tested before the password is compromised. Special characters are those characters that are not alphanumeric. Examples include: ~ ! @ # $ % ^ *.'
  desc  'rationale', ''
  desc  'check', "
    Login to the Workspace ONE Access admin console at \"https://<hostname>/SAAS/admin\" using administrative credentials.

    Click the \"Users and Groups\" tab then \"Settings\" to view the password policies.

    If \"Lowercase characters\" is not set to at least \"1\", this is a finding.
  "
  desc 'fix', "
    Login to the Workspace ONE Access admin console at \"https://<hostname>/SAAS/admin\" using administrative credentials.

    Click the \"Users and Groups\" tab then \"Settings\".

    Set \"Lowercase characters\" to \"1\" and click Save.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000167-AAA-000470'
  tag gid: 'V-WOAA-3X-000033'
  tag rid: 'SV-WOAA-3X-000033'
  tag stig_id: 'WOAA-3X-000033'
  tag cci: ['CCI-000193']
  tag nist: ['IA-5 (1) (a)']

  describe 'This control is a manual audit...skipping...' do
    skip 'This control is a manual audit...skipping...'
  end
end
