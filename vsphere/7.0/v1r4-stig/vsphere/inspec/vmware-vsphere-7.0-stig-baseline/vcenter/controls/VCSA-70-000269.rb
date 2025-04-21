control 'VCSA-70-000269' do
  title 'The vCenter Server must set the distributed port group Media Access Control (MAC) Address Change policy to "Reject".'
  desc 'If the virtual machine operating system changes the MAC address, it can send frames with an impersonated source MAC address at any time. This allows it to stage malicious attacks on the devices in a network by impersonating a network adaptor authorized by the receiving network.

This will prevent virtual machines from changing their effective MAC address and will affect applications that require this functionality. This will also affect how a layer 2 bridge will operate and will affect applications that require a specific MAC address for licensing.'
  desc 'check', 'If distributed switches are not used, this is not applicable.

From the vSphere Client, go to "Networking".

Select a distributed switch and then select a port group.

Select Configure >> Settings >> Policies.

Verify "MAC Address Changes" is set to "Reject".

or

From a PowerCLI command prompt while connected to the vCenter server, run the following commands:

Get-VDSwitch | Get-VDSecurityPolicy
Get-VDPortgroup | ?{$_.IsUplink -eq $false} | Get-VDSecurityPolicy

If the "MAC Address Changes" policy is set to "Accept", this is a finding.'
  desc 'fix', 'From the vSphere Client, go to "Networking".

Select a distributed switch and then select a port group.

Select Configure >> Settings >> Policies.

Click "Edit".

Click the "Security" tab.

Set "MAC Address Changes" to "Reject".

Click "OK".

or

From a PowerCLI command prompt while connected to the vCenter server, run the following commands:

Get-VDSwitch | Get-VDSecurityPolicy | Set-VDSecurityPolicy -MacChanges $false
Get-VDPortgroup | ?{$_.IsUplink -eq $false} | Get-VDSecurityPolicy | Set-VDSecurityPolicy -MacChanges $false'
  impact 0.5
  tag check_id: 'C-60024r885656_chk'
  tag severity: 'medium'
  tag gid: 'V-256349'
  tag rid: 'SV-256349r885658_rule'
  tag stig_id: 'VCSA-70-000269'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-59967r885657_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  command = 'Get-VDSwitch | Select -ExpandProperty Name'
  vdswitches = powercli_command(command).stdout.gsub("\r\n", "\n").split("\n")

  if vdswitches.empty?
    describe '' do
      skip 'No distributed switches found to check.'
    end
  else
    vdswitches.each do |vds|
      command = "(Get-VDSwitch -Name \"#{vds}\") | Get-VDSecurityPolicy | Select-Object -ExpandProperty MacChanges"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'false' }
      end
    end
  end

  command = 'Get-VDPortgroup | Where-Object {$_.IsUplink -eq $false} | Select -ExpandProperty Name'
  vdportgroups = powercli_command(command).stdout.gsub("\r\n", "\n").split("\n")

  if vdportgroups.empty?
    describe '' do
      skip 'No distributed port groups found to check.'
    end
  else
    vdportgroups.each do |vdpg|
      command = "(Get-VDPortgroup -Name \"#{vdpg}\") | Get-VDSecurityPolicy | Select-Object -ExpandProperty MacChanges"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'false' }
      end
    end
  end
end
