control 'VCSA-80-000079' do
  title 'The vCenter Server must enforce a 90-day maximum password lifetime restriction.'
  desc  "
    Any password, no matter how complex, can eventually be cracked. Therefore, passwords must be changed at specific intervals.

    One method of minimizing this risk is to use complex passwords and periodically change them. If the application does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the system and/or application passwords could be compromised.

    This requirement does not include emergency administration accounts, which are meant for access to the application in case of failure. These accounts are not required to have maximum password lifetime restrictions.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Local Accounts >> Password Policy.

    View the value of the \"Maximum lifetime\" setting.

    Maximum lifetime: Password must be changed every 90 days

    If the password policy is not configured with \"Maximum lifetime\" policy of \"90\" or less, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Local Accounts >> Password Policy.

    Click \"Edit\".

    Set \"Maximum lifetime\" to \"90\" and click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000174'
  tag gid: 'V-VCSA-80-000079'
  tag rid: 'SV-VCSA-80-000079'
  tag stig_id: 'VCSA-80-000079'
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']

  command = '(Get-SsoPasswordPolicy).PasswordLifetimeDays'
  describe powercli_command(command) do
    its('stdout.strip') { should cmp <= 90 }
  end
end
