control 'WOAA-3X-000031' do
  title 'Workspace ONE Access must be configured to prohibit password reuse for a minimum of five generations.'
  desc  "
    Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

    To meet password policy requirements, passwords need to be changed at specific policy-based intervals.

    If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.
  "
  desc  'rationale', ''
  desc  'check', "
    Login to the Workspace ONE Access admin console at \"https://<hostname>/SAAS/admin\" using administrative credentials.

    Click the \"Users and Groups\" tab then \"Settings\" to view the password policies.

    If \"Password history\" is not set to at least \"5\", this is a finding.
  "
  desc 'fix', "
    Login to the Workspace ONE Access admin console at \"https://<hostname>/SAAS/admin\" using administrative credentials.

    Click the \"Users and Groups\" tab then \"Settings\".

    Set \"Password history\" to at least \"5\" and click Save.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000165-AAA-000550'
  tag gid: 'V-WOAA-3X-000031'
  tag rid: 'SV-WOAA-3X-000031'
  tag stig_id: 'WOAA-3X-000031'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']

  describe 'This control is a manual audit...skipping...' do
    skip 'This control is a manual audit...skipping...'
  end
end
