control 'VCSA-80-000299' do
  title 'The vCenter Server must disable CDP/LLDP on distributed switches.'
  desc 'The vSphere Distributed Virtual Switch can participate in Cisco Discovery Protocol (CDP) or Link Layer Discovery Protocol (LLDP), as a listener, advertiser, or both. The information is sensitive, including IP addresses, system names, software versions, and more. It can be used by an adversary to gain a better understanding of your environment, and to impersonate devices. It is also transmitted unencrypted on the network, and as such the recommendation is to disable it.'
  desc 'check', 'If distributed switches are not used, this is not applicable.

From the vSphere Client, go to "Networking".

Select a distributed switch >> Configure >> Settings >> Properties.

Review the "Discovery Protocol" configuration.

or

From a PowerCLI command prompt while connected to the vCenter server, run the following command:

Get-VDSwitch | Select Name,LinkDiscoveryProtocolOperation

If any distributed switch does not have "Discovery Protocols" disabled, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to "Networking".

Select a distributed switch >> Configure >> Settings >> Properties.

Click "Edit".

Select the advanced tab and update the "Type" under "Discovery Protocol" to disabled and click "OK".

or

From a PowerCLI command prompt while connected to the vCenter server, run the following command:

Get-VDSwitch -Name "DSwitch" | Set-VDSwitch -LinkDiscoveryProtocolOperation "Disabled"'
  impact 0.3
  tag check_id: 'C-62704r934548_chk'
  tag severity: 'low'
  tag gid: 'V-258964'
  tag rid: 'SV-258964r961863_rule'
  tag stig_id: 'VCSA-80-000299'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-62613r934549_fix'
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
      command = "Get-VDSwitch -Name \"#{vds}\" | Select -ExpandProperty LinkDiscoveryProtocolOperation"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'Disabled' }
      end
    end
  end
end
