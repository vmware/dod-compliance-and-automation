control 'VCSA-80-000302' do
  title 'The vCenter Server must reset port configuration when virtual machines are disconnected.'
  desc 'Port-level configuration overrides are disabled by default. Once enabled, this allows for different security settings to be set from what is established at the Port Group level. If overrides are not monitored, anyone who gains access to a VM with a less secure VDS configuration could exploit that broader access.

If any unknown or unauthorized per-port overrides exist and are not discarded when a virtual machine is disconnected from that port then a future virtual machine connected to that port may receive a less secure port.'
  desc 'check', 'If distributed switches are not used, this is not applicable.

From the vSphere Client, go to "Networking".

Select a distributed switch >> Select a distributed port group >> Configure >> Settings >> Properties.

Review the "Configure reset at disconnect" setting.

or

From a PowerCLI command prompt while connected to the vCenter server, run the following command:

(Get-VDPortgroup).ExtensionData.Config.Policy.PortConfigResetAtDisconnect

If there are any distributed port groups with "Configure reset at disconnect" configured to "disabled" or "False", this is a finding.'
  desc 'fix', 'From the vSphere Client, go to "Networking".

Select a distributed switch >> Select a distributed port group >> Configure >> Settings >> Properties.

Click "Edit".

Select advanced and update "Configure reset at disconnect" to be enabled and click "OK".

or

From a PowerCLI command prompt while connected to the vCenter server, run the following command:

$pgs = Get-VDPortgroup | Get-View
ForEach($pg in $pgs){
$spec = New-Object VMware.Vim.DVPortgroupConfigSpec
$spec.configversion = $pg.Config.ConfigVersion
$spec.Policy = New-Object VMware.Vim.VMwareDVSPortgroupPolicy
$spec.Policy.PortConfigResetAtDisconnect = $True
$pg.ReconfigureDVPortgroup_Task($spec)
}'
  impact 0.5
  tag check_id: 'C-62707r934557_chk'
  tag severity: 'medium'
  tag gid: 'V-258967'
  tag rid: 'SV-258967r934559_rule'
  tag stig_id: 'VCSA-80-000302'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-62616r934558_fix'
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
      command = "(Get-VDPortgroup -Name \"#{vdpg}\").ExtensionData.Config.Policy.PortConfigResetAtDisconnect"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'True' }
      end
    end
  end
end
