control 'WOAA-3X-000040' do
  title 'Workspace ONE Access must be configured to enforce a 60-day maximum password lifetime restriction.'
  desc  "
    Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed at specific intervals.

    One method of minimizing this risk is to use complex passwords and periodically change them. If the application does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the system and/or application passwords could be compromised.

    This requirement does not include emergency administration accounts that are meant for access to the application in case of failure. These accounts are not required to have maximum password lifetime restrictions.
  "
  desc  'rationale', ''
  desc  'check', "
    Login to the Workspace ONE Access admin console at \"https://<hostname>/SAAS/admin\" using administrative credentials.

    Click the \"Users and Groups\" tab then \"Settings\" to view the password policies.

    If \"Password Lifetime\" is  set to a value greater than \"60\", this is a finding.
  "
  desc 'fix', "
    Login to the Workspace ONE Access admin console at \"https://<hostname>/SAAS/admin\" using administrative credentials.

    Click the \"Users and Groups\" tab then \"Settings\".

    Set \"Password Lifetime\" to a value lesser than \"60\" but geater than \"1\" and click Save.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000174-AAA-000540'
  tag gid: 'V-WOAA-3X-000040'
  tag rid: 'SV-WOAA-3X-000040'
  tag stig_id: 'WOAA-3X-000040'
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']

  describe 'This control is a manual audit...skipping...' do
    skip 'This control is a manual audit...skipping...'
  end
end
