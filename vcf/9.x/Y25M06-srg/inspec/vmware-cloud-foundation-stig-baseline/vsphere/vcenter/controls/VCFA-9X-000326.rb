control 'VCFA-9X-000326' do
  title 'The VMware Cloud Foundation vCenter Server must only send NetFlow traffic to authorized collectors.'
  desc  'The distributed virtual switch can export NetFlow information about traffic crossing the switch. NetFlow exports are not encrypted and can contain information about the virtual network, making it easier for a man-in-the-middle attack to be executed successfully. If NetFlow export is required, verify that all NetFlow target Internet Protocol (IP) addresses are correct.'
  desc  'rationale', ''
  desc  'check', "
    If distributed switches are not used, this is not applicable.

    To view NetFlow Collector IPs configured on distributed switches:

    From the vSphere Client, go to \"Networking\".

    Select a distributed switch >> Configure >> Settings >> NetFlow.

    View the NetFlow pane and verify any collector IP addresses are valid and in use for troubleshooting.

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following command:

    Get-VDSwitch | select Name,@{N=\"NetFlowCollectorIPs\";E={$_.ExtensionData.config.IpfixConfig.CollectorIpAddress}}

    To view if NetFlow is enabled on any distributed port groups:

    From the vSphere Client, go to \"Networking\".

    Select a distributed port group >> Manage >> Settings >> Policies.

    Go to \"Monitoring\" and view the NetFlow status.

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following command:

    Get-VDPortgroup | Select Name,VirtualSwitch,@{N=\"NetFlowEnabled\";E={$_.Extensiondata.Config.defaultPortConfig.ipfixEnabled.Value}}

    If NetFlow is configured and the collector IP is not known and documented, this is a finding.
  "
  desc 'fix', "
    To remove collector IPs, do the following:

    From the vSphere Client, go to \"Networking\".

    Select a distributed switch >> Configure >> Settings >> NetFlow.

    Click \"Edit\".

    Remove any unknown collector IPs.

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following commands:

    $dvs = Get-VDSwitch dvswitch | Get-View
    ForEach($vs in $dvs){
    $spec = New-Object VMware.Vim.VMwareDVSConfigSpec
    $spec.configversion = $vs.Config.ConfigVersion
    $spec.IpfixConfig = New-Object VMware.Vim.VMwareIpfixConfig
    $spec.IpfixConfig.CollectorIpAddress = \"\"
    $spec.IpfixConfig.CollectorPort = \"0\"
    $spec.IpfixConfig.ActiveFlowTimeout = \"60\"
    $spec.IpfixConfig.IdleFlowTimeout = \"15\"
    $spec.IpfixConfig.SamplingRate = \"0\"
    $spec.IpfixConfig.InternalFlowsOnly = $False
    $vs.ReconfigureDvs_Task($spec)
    }

    Note: This will reset the NetFlow collector configuration back to the defaults.

    To disable NetFlow on a distributed port group, do the following:

    From the vSphere Client, go to \"Networking\".

    Select a distributed port group >> Configure >> Settings >> Policies.

    Click \"Edit\".

    Click the \"Monitoring\" tab.

    Change \"NetFlow\" to \"Disabled\".

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following commands:

    $pgs = Get-VDPortgroup | Where-Object {$_.ExtensionData.Config.BackingType -eq \"standard\" -and $_.IsUplink -eq $false} | Get-View
    ForEach($pg in $pgs){
    $spec = New-Object VMware.Vim.DVPortgroupConfigSpec
    $spec.configversion = $pg.Config.ConfigVersion
    $spec.defaultPortConfig = New-Object VMware.Vim.VMwareDVSPortSetting
    $spec.defaultPortConfig.ipfixEnabled = New-Object VMware.Vim.BoolPolicy
    $spec.defaultPortConfig.ipfixEnabled.inherited = $false
    $spec.defaultPortConfig.ipfixEnabled.value = $false
    $pg.ReconfigureDVPortgroup_Task($spec)
    }
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516'
  tag gid: 'V-VCFA-9X-000326'
  tag rid: 'SV-VCFA-9X-000326'
  tag stig_id: 'VCFA-9X-000326'
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
      command = "(Get-VDSwitch -Name \"#{vds}\").ExtensionData.Config.IpfixConfig | ConvertTo-Json -Depth 2 -WarningAction SilentlyContinue"
      result = powercli_command(command).stdout.strip

      if result.blank?
        describe "No results returned from command: #{command} . Troubleshoot issue and rerun scan." do
          skip "No results returned from command: #{command} . Troubleshoot issue and rerun scan."
        end
      else
        resultjson = json(content: result)
        if !resultjson['CollectorIpAddress'].blank?
          describe "The distributed switch with name: #{vds} and setting" do
            subject { resultjson }
            its(['CollectorIpAddress']) { should be_in "#{input('vcenter_ipfixCollectorAddresses')}" }
          end
        else
          describe "The distributed switch with name: #{vds} and setting" do
            subject { json(content: result) }
            its(['CollectorIpAddress']) { should be_blank }
          end
        end
      end
    end
  end
end
