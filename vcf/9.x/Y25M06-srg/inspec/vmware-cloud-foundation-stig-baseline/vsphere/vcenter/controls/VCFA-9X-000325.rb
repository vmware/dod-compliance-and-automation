control 'VCFA-9X-000325' do
  title 'The VMware Cloud Foundation vCenter Server must set the distributed port group Promiscuous Mode policy to "Reject".'
  desc  "
    When promiscuous mode is enabled for a virtual switch, all virtual machines connected to the port group have the potential of reading all packets across that network, meaning only the virtual machines connected to that port group.

    Promiscuous mode is disabled by default on the ESXi Server, and this is the recommended setting.
  "
  desc  'rationale', ''
  desc  'check', "
    If distributed switches are not used, this is not applicable.

    From the vSphere Client, go to \"Networking\".

    Select a distributed switch >> Select a port group >> Configure >> Settings >> Policies.

    Verify \"Promiscuous Mode\" is set to \"Reject\".

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following command:

    Get-VDPortgroup | Where-Object {$_.ExtensionData.Config.BackingType -eq \"standard\" -and $_.IsUplink -eq $false} | Get-VDSecurityPolicy

    If the \"Promiscuous Mode\" policy is set to accept on a nonuplink port group, this is a finding.

    Note: Uplink and NSX backed distributed port groups are not in scope of this rule.
  "
  desc 'fix', "
    From the vSphere Client, go to \"Networking\".

    Select a distributed switch >> Select a port group >> Configure >> Settings >> Policies.

    Click \"Edit\".

    Click the \"Security\" tab.

    Set \"Promiscuous Mode\" to \"Reject\".

    Click \"OK\".

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following command:

    Get-VDPortgroup | Where-Object {$_.ExtensionData.Config.BackingType -eq \"standard\" -and $_.IsUplink -eq $false} | Get-VDSecurityPolicy | Set-VDSecurityPolicy -AllowPromiscuous $false
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516'
  tag gid: 'V-VCFA-9X-000325'
  tag rid: 'SV-VCFA-9X-000325'
  tag stig_id: 'VCFA-9X-000325'
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
          its(['AllowPromiscuous']) { should cmp 'false' }
        end
      end
    end
  end
end
