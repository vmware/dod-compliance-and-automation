control 'VCFA-9X-000341' do
  title 'The VMware Cloud Foundation vCenter Server must not override port group settings at the port level on distributed switches.'
  desc  "
    Port-level configuration overrides are disabled by default. Once enabled, this allows for different security settings to be set from what is established at the Port Group level. If overrides are not monitored, anyone who gains access to a VM with a less secure VDS configuration could exploit that broader access.

    If there are cases where particular VMs require unique configurations then a different port group with the required configuration should be created instead of overriding port group settings.
  "
  desc  'rationale', ''
  desc  'check', "
    If distributed switches are not used, this is not applicable.

    From the vSphere Client, go to \"Networking\".

    Select a distributed switch >> Select a distributed port group >> Configure >> Settings >> Properties.

    Review the \"Override port policies\".

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following command:

    (Get-VDPortgroup | Where-Object {$_.ExtensionData.Config.BackingType -eq \"standard\" -and $_.IsUplink -eq $false}).ExtensionData.Config.Policy

    If there are any distributed port groups that allow overridden port policies, this is a finding.

    Note: This does not apply to the \"Block Ports\" or \"Configure reset at disconnect\" policies.

    Note: Uplink and NSX backed distributed port groups are not in scope of this rule.
  "
  desc 'fix', "
    From the vSphere Client, go to \"Networking\".

    Select a distributed switch >> Select a distributed port group >> Configure >> Settings >> Properties.

    Click \"Edit\".

    Select advanced and update all port policies besides \"Block Ports\" to \"disabled\" and click \"OK\".

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following command:

    $pgs = Get-VDPortgroup | Where-Object {$_.ExtensionData.Config.BackingType -eq \"standard\" -and $_.IsUplink -eq $false}) | Get-View
    ForEach($pg in $pgs){
      $spec = New-Object VMware.Vim.DVPortgroupConfigSpec
      $spec.configversion = $pg.Config.ConfigVersion
      $spec.Policy = New-Object VMware.Vim.VMwareDVSPortgroupPolicy
      $spec.Policy.VlanOverrideAllowed = $False
      $spec.Policy.UplinkTeamingOverrideAllowed = $False
      $spec.Policy.SecurityPolicyOverrideAllowed = $False
      $spec.Policy.IpfixOverrideAllowed = $False
      $spec.Policy.MacManagementOverrideAllowed = $False
      $spec.Policy.BlockOverrideAllowed = $True
      $spec.Policy.ShapingOverrideAllowed = $False
      $spec.Policy.VendorConfigOverrideAllowed = $False
      $spec.Policy.LivePortMovingAllowed = $False
      $spec.Policy.PortConfigResetAtDisconnect = $True
      $spec.Policy.NetworkResourcePoolOverrideAllowed = $False
      $spec.Policy.TrafficFilterOverrideAllowed = $False
      $pg.ReconfigureDVPortgroup_Task($spec)
    }

    Note: All port group policies must be specified or they will be set to false.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516'
  tag gid: 'V-VCFA-9X-000341'
  tag rid: 'SV-VCFA-9X-000341'
  tag stig_id: 'VCFA-9X-000341'
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
      command = "(Get-VDPortGroup -Name \"#{vdpg}\").ExtensionData.Config.Policy | ConvertTo-Json -Depth 1 -WarningAction SilentlyContinue"
      result = powercli_command(command).stdout.strip

      if result.blank?
        describe "No results returned from command: #{command} . Troubleshoot issue and rerun scan." do
          skip "No results returned from command: #{command} . Troubleshoot issue and rerun scan."
        end
      else
        resultjson = json(content: result)
        describe "The distributed portgroup with name: #{vdpg} and setting" do
          subject { resultjson }
          its(['VlanOverrideAllowed']) { should cmp 'false' }
          its(['UplinkTeamingOverrideAllowed']) { should cmp 'false' }
          its(['SecurityPolicyOverrideAllowed']) { should cmp 'false' }
          its(['IpfixOverrideAllowed']) { should cmp 'false' }
          its(['MacManagementOverrideAllowed']) { should cmp 'false' }
          its(['ShapingOverrideAllowed']) { should cmp 'false' }
          its(['VendorConfigOverrideAllowed']) { should cmp 'false' }
          its(['LivePortMovingAllowed']) { should cmp 'false' }
          its(['NetworkResourcePoolOverrideAllowed']) { should cmp 'false' }
          its(['TrafficFilterOverrideAllowed']) { should cmp 'false' }
        end
      end
    end
  end
end
