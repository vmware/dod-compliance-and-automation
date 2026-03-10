control 'VCFA-9X-000339' do
  title 'The VMware Cloud Foundation vCenter Server must disable CDP/LLDP on distributed switches.'
  desc  'The vSphere Distributed Virtual Switch can participate in Cisco Discovery Protocol (CDP) or Link Layer Discovery Protocol (LLDP) as a listener, advertiser, or both. The information is sensitive, including IP addresses, system names, software versions, and more. It can be used by an adversary to gain a better understanding of your environment, and to impersonate devices. It is also transmitted unencrypted on the network, and as such the recommendation is to disable it.'
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
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516'
  tag gid: 'V-VCFA-9X-000339'
  tag rid: 'SV-VCFA-9X-000339'
  tag stig_id: 'VCFA-9X-000339'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  command = 'Get-VDSwitch | Select -ExpandProperty Name'
  vdswitches = powercli_command(command).stdout.gsub("\r\n", "\n").split("\n")

  if vdswitches.blank?
    impact 0.0
    describe 'No distributed switches found to audit. This is not applicable.' do
      skip 'No distributed switches found to audit. This is not applicable.'
    end
  else
    vdswitches.each do |vds|
      command = "Get-VDSwitch -Name \"#{vds}\" | Select-Object Name,LinkDiscoveryProtocolOperation | ConvertTo-Json -Depth 1 -WarningAction SilentlyContinue"
      result = powercli_command(command).stdout.strip

      if result.blank?
        describe "No results returned from command: #{command} . Troubleshoot issue and rerun scan." do
          skip "No results returned from command: #{command} . Troubleshoot issue and rerun scan."
        end
      else
        resultjson = json(content: result)
        # The value is converted to a number when converted to json. 3 is disabled.
        describe "Discovery protocol on distributed switch with name: #{vds}" do
          subject { resultjson['LinkDiscoveryProtocolOperation'] }
          it { should cmp 3 }
        end
      end
    end
  end
end
