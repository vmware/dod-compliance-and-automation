control 'VCFA-9X-000323' do
  title 'The VMware Cloud Foundation vCenter Server must set the distributed port group Forged Transmits policy to "Reject".'
  desc  "
    If the virtual machine operating system changes the Media Access Control (MAC) address, the operating system can send frames with an impersonated source MAC address at any time. This allows an operating system to stage malicious attacks on the devices in a network by impersonating a network adaptor authorized by the receiving network.

    When the \"Forged Transmits\" option is set to \"Accept\", ESXi does not compare source and effective MAC addresses.

    To protect against MAC impersonation, set the \"Forged Transmits\" option to \"Reject\". The host compares the source MAC address being transmitted by the guest operating system with the effective MAC address for its virtual machine adapter to determine if they match. If the addresses do not match, the ESXi host drops the packet.
  "
  desc  'rationale', ''
  desc  'check', "
    If distributed switches are not used, this is not applicable.

    From the vSphere Client, go to \"Networking\".

    Select a distributed switch >> Select a port group >> Configure >> Settings >> Policies.

    Verify \"Forged Transmits\" is set to \"Reject\".

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following command:

    Get-VDPortgroup | Where-Object {$_.ExtensionData.Config.BackingType -eq \"standard\" -and $_.IsUplink -eq $false} | Get-VDSecurityPolicy

    If the \"Forged Transmits\" policy is set to accept on a nonuplink port group, this is a finding.

    Note: Uplink and NSX backed distributed port groups are not in scope of this rule.
  "
  desc 'fix', "
    From the vSphere Client, go to \"Networking\".

    Select a distributed switch >> Select a port group >> Configure >> Settings >> Policies.

    Click \"Edit\".

    Click the \"Security\" tab.

    Set \"Forged Transmits\" to \"Reject\".

    Click \"OK\".

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following command:

    Get-VDPortgroup | Where-Object {$_.ExtensionData.Config.BackingType -eq \"standard\" -and $_.IsUplink -eq $false} | Get-VDSecurityPolicy | Set-VDSecurityPolicy -ForgedTransmits $false
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516'
  tag gid: 'V-VCFA-9X-000323'
  tag rid: 'SV-VCFA-9X-000323'
  tag stig_id: 'VCFA-9X-000323'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  command = 'Get-VDPortgroup | Where-Object {$_.ExtensionData.Config.BackingType -eq "standard" -and $_.IsUplink -eq $false} | Select -ExpandProperty Name'
  vdportgroups = powercli_command(command).stdout.gsub("\r\n", "\n").split("\n")

  if vdportgroups.blank?
    impact 0.0
    describe 'No distributed portgroups found. This is not applicable.' do
      skip 'No distributed portgroups found. This is not applicable.'
    end
  else
    vdportgroups.each do |vdpg|
      command = "Get-VDPortGroup -Name \"#{vdpg}\" | Get-VDSecurityPolicy | Select VDPortgroup,AllowPromiscuous,MacChanges,ForgedTransmits | ConvertTo-Json -Depth 0 -WarningAction SilentlyContinue"
      result = powercli_command(command).stdout.strip

      if result.blank?
        describe "No results returned from command: #{command} . Troubleshoot issue and rerun scan." do
          skip "No results returned from command: #{command} . Troubleshoot issue and rerun scan."
        end
      else
        resultjson = json(content: result)
        describe "The distributed portgroup with name: #{vdpg} and setting" do
          subject { resultjson }
          its(['ForgedTransmits']) { should cmp 'false' }
        end
      end
    end
  end
end
