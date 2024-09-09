control 'VCSA-80-000270' do
  title 'The vCenter Server must set the distributed port group Promiscuous Mode policy to "Reject".'
  desc 'When promiscuous mode is enabled for a virtual switch, all virtual machines connected to the port group have the potential of reading all packets across that network, meaning only the virtual machines connected to that port group.

Promiscuous mode is disabled by default on the ESXi Server, and this is the recommended setting.'
  desc 'check', 'If distributed switches are not used, this is not applicable.

From the vSphere Client, go to "Networking".

Select a distributed switch >> Select a port group >> Configure >> Settings >> Policies.

Verify "Promiscuous Mode" is set to "Reject".

or

From a PowerCLI command prompt while connected to the vCenter server, run the following commands:

Get-VDSwitch | Get-VDSecurityPolicy
Get-VDPortgroup | ?{$_.IsUplink -eq $false} | Get-VDSecurityPolicy

If the "Promiscuous Mode" policy is set to accept, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to "Networking".

Select a distributed switch >> Select a port group >> Configure >> Settings >> Policies.

Click "Edit".

Click the "Security" tab.

Set "Promiscuous Mode" to "Reject".

Click "OK".

or

From a PowerCLI command prompt while connected to the vCenter server, run the following commands:

Get-VDSwitch | Get-VDSecurityPolicy | Set-VDSecurityPolicy -AllowPromiscuous $false
Get-VDPortgroup | ?{$_.IsUplink -eq $false} | Get-VDSecurityPolicy | Set-VDSecurityPolicy -AllowPromiscuous $false'
  impact 0.5
  tag check_id: 'C-62677r934467_chk'
  tag severity: 'medium'
  tag gid: 'V-258937'
  tag rid: 'SV-258937r961863_rule'
  tag stig_id: 'VCSA-80-000270'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-62586r934468_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  command = 'Get-VDSwitch | Select -ExpandProperty Name'
  vdswitches = powercli_command(command).stdout.gsub("\r\n", "\n").split("\n")

  if vdswitches.empty?
    impact 0.0
    describe 'No distributed switches found. This is not applicable.' do
      skip 'No distributed switches found. This is not applicable.'
    end
  else
    vdswitches.each do |vds|
      command = "(Get-VDSwitch -Name \"#{vds}\") | Get-VDSecurityPolicy | Select-Object -ExpandProperty AllowPromiscuous"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'false' }
      end
    end
    command = 'Get-VDPortgroup | Where-Object {$_.IsUplink -eq $false} | Select -ExpandProperty Name'
    vdportgroups = powercli_command(command).stdout.gsub("\r\n", "\n").split("\n")

    if vdportgroups.empty?
      describe 'No distributed port groups found.' do
        skip 'No distributed port groups found.'
      end
    else
      vdportgroups.each do |vdpg|
        command = "(Get-VDPortgroup -Name \"#{vdpg}\") | Get-VDSecurityPolicy | Select-Object -ExpandProperty AllowPromiscuous"
        describe powercli_command(command) do
          its('stdout.strip') { should cmp 'false' }
        end
      end
    end
  end
end
