control 'VCSA-80-000301' do
  title 'The vCenter Server must not override port group settings at the port level on distributed switches.'
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

    (Get-VDPortgroup).ExtensionData.Config.Policy

    If there are any distributed port groups that allow overridden port policies, this is a finding.

    Note: This does not apply to the \"Block Ports\" or \"Configure reset at disconnect\" policies.
  "
  desc 'fix', "
    From the vSphere Client, go to \"Networking\".

    Select a distributed switch >> Select a distributed port group >> Configure >> Settings >> Properties.

    Click \"Edit\".

    Select advanced and update all port policies besides \"Block Ports\" to \"disabled\" and click \"OK\".

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following command:

    $pgs = Get-VDPortgroup | Get-View
    ForEach($pg in $pgs){
    $spec = New-Object VMware.Vim.DVPortgroupConfigSpec
    $spec.configversion = $pg.Config.ConfigVersion
    $spec.Policy = New-Object VMware.Vim.VMwareDVSPortgroupPolicy
    $spec.Policy.VlanOverrideAllowed = $False
    $spec.Policy.UplinkTeamingOverrideAllowed = $False
    $spec.Policy.SecurityPolicyOverrideAllowed = $False
    $spec.Policy.IpfixOverrideAllowed = $False
    $spec.Policy.BlockOverrideAllowed = $True
    $spec.Policy.ShapingOverrideAllowed = $False
    $spec.Policy.VendorConfigOverrideAllowed = $False
    $spec.Policy.TrafficFilterOverrideAllowed = $False
    $pg.ReconfigureDVPortgroup_Task($spec)
    }
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516'
  tag gid: 'V-VCSA-80-000301'
  tag rid: 'SV-VCSA-80-000301'
  tag stig_id: 'VCSA-80-000301'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  command = 'Get-VDPortgroup | Select -ExpandProperty Name'
  vdportgroups = powercli_command(command).stdout.gsub("\r\n", "\n").split("\n")

  if vdportgroups.empty?
    describe '' do
      skip 'No distributed port groups found to check.'
    end
  else
    vdportgroups.each do |vdpg|
      command = "(Get-VDPortgroup -Name \"#{vdpg}\").ExtensionData.Config.Policy.VlanOverrideAllowed"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'False' }
      end
      command = "(Get-VDPortgroup -Name \"#{vdpg}\").ExtensionData.Config.Policy.UplinkTeamingOverrideAllowed"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'False' }
      end
      command = "(Get-VDPortgroup -Name \"#{vdpg}\").ExtensionData.Config.Policy.SecurityPolicyOverrideAllowed"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'False' }
      end
      command = "(Get-VDPortgroup -Name \"#{vdpg}\").ExtensionData.Config.Policy.IpfixOverrideAllowed"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'False' }
      end
      command = "(Get-VDPortgroup -Name \"#{vdpg}\").ExtensionData.Config.Policy.MacManagementOverrideAllowed"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'False' }
      end
      command = "(Get-VDPortgroup -Name \"#{vdpg}\").ExtensionData.Config.Policy.ShapingOverrideAllowed"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'False' }
      end
      command = "(Get-VDPortgroup -Name \"#{vdpg}\").ExtensionData.Config.Policy.VendorConfigOverrideAllowed"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'False' }
      end
      command = "(Get-VDPortgroup -Name \"#{vdpg}\").ExtensionData.Config.Policy.LivePortMovingAllowed"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'False' }
      end
      command = "(Get-VDPortgroup -Name \"#{vdpg}\").ExtensionData.Config.Policy.NetworkResourcePoolOverrideAllowed"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'False' }
      end
      command = "(Get-VDPortgroup -Name \"#{vdpg}\").ExtensionData.Config.Policy.TrafficFilterOverrideAllowed"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'False' }
      end
    end
  end
end
