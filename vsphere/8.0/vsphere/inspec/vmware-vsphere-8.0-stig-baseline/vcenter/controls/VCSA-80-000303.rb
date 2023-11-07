control 'VCSA-80-000303' do
  title 'The vCenter Server must disable Secure Shell (SSH) access.'
  desc 'vCenter Server is delivered as an appliance, and intended to be managed through the VAMI, vSphere Client, and APIs. SSH is a troubleshooting and support tool and should only be enabled when necessary.

vCenter Server High Availability uses SSH to coordinate the replication and failover between the nodes. Use of this feature requires SSH to remain enabled.'
  desc 'check', 'Open the Virtual Appliance Management Interface (VAMI) by navigating to https://<vCenter server>:5480.

Log in with local operating system administrative credentials or with a Single Sign-On (SSO) account that is a member of the "SystemConfiguration.BashShellAdministrator" group.

Select "Access" on the left navigation pane.

If "SSH Login" is not "Deactivated", this is a finding.'
  desc 'fix', 'Open the Virtual Appliance Management Interface (VAMI) by navigating to https://<vCenter server>:5480.

Log in with local operating system administrative credentials or with a Single Sign-On (SSO) account that is a member of the "SystemConfiguration.BashShellAdministrator" group.

Select "Access" on the left navigation pane.

Click "Edit" then disable "Activate SSH Login" and click "OK".'
  impact 0.5
  tag check_id: 'C-62708r934560_chk'
  tag severity: 'medium'
  tag gid: 'V-258968'
  tag rid: 'SV-258968r934562_rule'
  tag stig_id: 'VCSA-80-000303'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-62617r934561_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe powercli_command('Invoke-GetAccessSsh').stdout.strip do
    it { should_not cmp 'true' }
  end
end
