control 'VCSA-80-000305' do
  title 'The vCenter Server must disable accounts used for Integrated Windows Authentication (IWA).'
  desc 'If not used for their intended purpose, default accounts must be disabled. vCenter ships with several default accounts, two of which are specific to IWA and SASL/Kerberos authentication. If other methods of authentication are used, these accounts are not needed and must be disabled.'
  desc 'check', 'If IWA is used for vCenter authentication, this is not applicable.

From the vSphere Client, go to Administration >> Single Sign On >> Users and Groups >> Users.

Change the domain to "vsphere.local" and review the "K/M" and "krbtgt/VSPHERE.LOCAL" accounts.

If the "K/M" and "krbtgt/VSPHERE.LOCAL" accounts are not disabled, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Administration >> Single Sign On >> Users and Groups >> Users.

Select the "K/M" or "krbtgt/VSPHERE.LOCAL" and click "More" then select "Disable".

Click "Ok" to disable the user account.'
  impact 0.5
  tag check_id: 'C-69902r1003614_chk'
  tag severity: 'medium'
  tag gid: 'V-265979'
  tag rid: 'SV-265979r1003616_rule'
  tag stig_id: 'VCSA-80-000305'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-69805r1003615_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if input('iwaEnabled')
    impact 0.0
    describe 'Integrated Windows Authentication specified as in use. This control is not applicable' do
      skip 'Integrated Windows Authentication specified as in use. This control is not applicable'
    end
  else
    describe powercli_command('Get-SsoPersonUser -Domain vsphere.local -Name "K/M" | Select-Object -ExpandProperty Disabled') do
      its('stdout.strip') { should cmp 'true' }
    end
    describe powercli_command('Get-SsoPersonUser -Domain vsphere.local -Name "krbtgt/VSPHERE.LOCAL" | Select-Object -ExpandProperty Disabled') do
      its('stdout.strip') { should cmp 'true' }
    end
  end
end
