control 'VCSA-70-000079' do
  title 'The vCenter Server must enforce a 60-day maximum password lifetime restriction.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords must be changed at specific intervals.

One method of minimizing this risk is to use complex passwords and periodically change them. If the application does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the system and/or application passwords could be compromised.

This requirement does not include emergency administration accounts, which are meant for access to the application in case of failure. These accounts are not required to have maximum password lifetime restrictions.'
  desc 'check', 'From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Local Accounts >> Password Policy.

View the value of the "Maximum lifetime" setting.

If the "Maximum lifetime" policy is not set to "60", this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Local Accounts >> Password Policy.

Click "Edit", enter "60" into the "Maximum lifetime" setting, and click "OK".'
  impact 0.5
  tag check_id: 'C-60007r885605_chk'
  tag severity: 'medium'
  tag gid: 'V-256332'
  tag rid: 'SV-256332r885607_rule'
  tag stig_id: 'VCSA-70-000079'
  tag gtitle: 'SRG-APP-000174'
  tag fix_id: 'F-59950r885606_fix'
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']

  command = '(Get-SsoPasswordPolicy).PasswordLifetimeDays'
  describe powercli_command(command) do
    its('stdout.strip') { should cmp '60' }
  end
end
