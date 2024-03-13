control 'VCSA-80-000299' do
  title 'The vCenter Server must disable CDP/LLDP on distributed switches.'
  desc  'The vSphere Distributed Virtual Switch can participate in Cisco Discovery Protocol (CDP) or Link Layer Discovery Protocol (LLDP), as a listener, advertiser, or both. The information is sensitive, including IP addresses, system names, software versions, and more. It can be used by an adversary to gain a better understanding of your environment, and to impersonate devices. It is also transmitted unencrypted on the network, and as such the recommendation is to disable it.'
  desc  'rationale', ''
  desc  'check', "
    If distributed switches are not used, this is not applicable.

    From the vSphere Client, go to \"Networking\".

    Select a distributed switch >> Configure >> Settings >> Properties.

    Review the \"Discovery Protocol\" configuration.

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following command:

    Get-VDSwitch | Select Name,LinkDiscoveryProtocolOperation

    If any distributed switch does not have \"Discovery Protocols\" disabled, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to \"Networking\".

    Select a distributed switch >> Configure >> Settings >> Properties.

    Click \"Edit\".

    Select the advanced tab and update the \"Type\" under \"Discovery Protocol\" to disabled and click \"OK\".

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following command:

    Get-VDSwitch -Name \"DSwitch\" | Set-VDSwitch -LinkDiscoveryProtocolOperation \"Disabled\"
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-APP-000516'
  tag gid: 'V-VCSA-80-000299'
  tag rid: 'SV-VCSA-80-000299'
  tag stig_id: 'VCSA-80-000299'
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
      command = "Get-VDSwitch -Name \"#{vds}\" | Select -ExpandProperty LinkDiscoveryProtocolOperation"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'Disabled' }
      end
    end
  end
end
