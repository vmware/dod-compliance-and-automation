control 'VCFA-9X-000252' do
  title 'The VMware Cloud Foundation vCenter Server must disable the distributed virtual switch health check.'
  desc  'Network health check is disabled by default in vCenter. Once enabled, the health check packets contain information on host#, vds#, and port#, which an attacker would find useful. It is recommended that network health check be used only for troubleshooting and turned off when troubleshooting is finished.'
  desc  'rationale', ''
  desc  'check', "
    If distributed switches are not used, this is not applicable.

    From the vSphere Client, go to \"Networking\".

    Select a distributed switch >> Configure >> Settings >> Health Check.

    View the health check pane and verify the \"VLAN and MTU\" and \"Teaming and failover\" checks are \"Disabled\".

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following commands:

    $vds = Get-VDSwitch
    $vds.ExtensionData.Config.HealthCheckConfig

    If the health check feature is enabled on distributed switches and is not on temporarily for troubleshooting purposes, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to \"Networking\".

    Select a distributed switch >> Configure >> Settings >> Health Check.

    Click \"Edit\".

    Disable the \"VLAN and MTU\" and \"Teaming and failover\" checks.

    Click \"OK\".

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following command:

    Get-View -ViewType DistributedVirtualSwitch | ?{($_.config.HealthCheckConfig | ?{$_.enable -notmatch \"False\"})}| %{$_.UpdateDVSHealthCheckConfig(@((New-Object Vmware.Vim.VMwareDVSVlanMtuHealthCheckConfig -property @{enable=0}),(New-Object Vmware.Vim.VMwareDVSTeamingHealthCheckConfig -property @{enable=0})))}
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516'
  tag gid: 'V-VCFA-9X-000252'
  tag rid: 'SV-VCFA-9X-000252'
  tag stig_id: 'VCFA-9X-000252'
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
      command = "(Get-VDSwitch -Name \"#{vds}\").ExtensionData.Config.HealthCheckConfig | ConvertTo-Json -Depth 2 -WarningAction SilentlyContinue"
      result = powercli_command(command).stdout.strip

      if result.blank?
        describe "No results returned from command: #{command} . Troubleshoot issue and rerun scan." do
          skip "No results returned from command: #{command} . Troubleshoot issue and rerun scan."
        end
      else
        resultjson = json(content: result)
        resultjson.each do |hc|
          # There are 2 settings that should be false. PowerCLI does not return info about the settings itself just 2 enable true/false values
          describe "The health check status on distributed switch with name: #{vds}" do
            subject { hc['Enable'] }
            it { should cmp 'false' }
          end
        end
      end
    end
  end
end
