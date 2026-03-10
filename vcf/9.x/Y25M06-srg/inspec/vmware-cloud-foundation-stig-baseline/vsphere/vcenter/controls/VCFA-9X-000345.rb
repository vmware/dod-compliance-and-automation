control 'VCFA-9X-000345' do
  title 'The VMware Cloud Foundation vCenter Server must disable the distributed port group Media Access Control (MAC) learning policy.'
  desc  'MAC Learning enables a distributed switch to provide network connectivity to systems where more than one MAC address is used on a vNIC. This can be useful in special cases like nested virtualization (running ESXi inside ESXi, for example). MAC Learning also supports unknown unicast flooding. Normally, when a packet that is received by a port has an unknown destination MAC address, the packet is dropped. With unknown unicast flooding enabled, the port floods unknown unicast traffic to every port on the switch that has MAC Learning and unknown unicast flooding enabled. This property is enabled by default, but only if MAC Learning is enabled. It is recommended to disable MAC Learning unless it is in use intentionally for a known workload that requires it.'
  desc  'rationale', ''
  desc  'check', "
    If distributed switches are not used, this is not applicable.

    From the vSphere Client, go to \"Networking\".

    Select a distributed switch >> Select a port group >> Configure >> Settings >> Policies.

    Verify the \"MAC Learning\" status is set to \"Disabled\".

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following command:

    Get-VDPortgroup | Where-Object {$_.ExtensionData.Config.BackingType -eq \"standard\" -and $_.IsUplink -eq $false} | Select-Object Name,@{N=\\\"MAC Learning Enabled\\\";E={$_.ExtensionData.Config.DefaultPortConfig.MacManagementPolicy.MacLearningPolicy.Enabled}}

    If the \"MAC Learning\" policy is enabled on any port group, this is a finding.

    Note: Uplink and NSX backed distributed port groups are not in scope of this rule.
  "
  desc 'fix', "
    From the vSphere Client, go to \"Networking\".

    Select a distributed switch >> Select a port group >> Configure >> Settings >> Policies.

    Click \"Edit\".

    Click the \"Security\" tab.

    Set the \"MAC Learning\" status to \"Disabled\".

    Click \"OK\".

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following commands:

    $pgs = Get-VDPortgroup | Where-Object {$_.ExtensionData.Config.BackingType -eq \"standard\" -and $_.IsUplink -eq $false} | Get-View
    ForEach($pg in $pgs){
      $spec = New-Object VMware.Vim.DVPortgroupConfigSpec
      $spec.DefaultPortConfig = New-Object VMware.Vim.VMwareDVSPortSetting
      $spec.DefaultPortConfig.MacManagementPolicy = New-Object VMware.Vim.DVSMacManagementPolicy
      $spec.DefaultPortConfig.MacManagementPolicy.MacLearningPolicy = New-Object VMware.Vim.DVSMacLearningPolicy
      $spec.DefaultPortConfig.MacManagementPolicy.MacLearningPolicy.Enabled = $false
      $spec.ConfigVersion = $pg.Config.ConfigVersion
      $pg.ReconfigureDVPortgroup_Task($spec)
    }
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516'
  tag gid: 'V-VCFA-9X-000345'
  tag rid: 'SV-VCFA-9X-000345'
  tag stig_id: 'VCFA-9X-000345'
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
      command = "(Get-VDPortGroup -Name \"#{vdpg}\").ExtensionData.Config.DefaultPortConfig.MacManagementPolicy.MacLearningPolicy | ConvertTo-Json -Depth 1 -WarningAction SilentlyContinue"
      result = powercli_command(command).stdout.strip

      if result.blank?
        describe "No results returned from command: #{command} . Troubleshoot issue and rerun scan." do
          skip "No results returned from command: #{command} . Troubleshoot issue and rerun scan."
        end
      else
        resultjson = json(content: result)
        describe "The MAC learning policy on distributed portgroup: #{vdpg}" do
          subject { resultjson }
          its(['Enabled']) { should cmp 'false' }
        end
      end
    end
  end
end
