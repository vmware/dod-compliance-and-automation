control 'VCFA-9X-000105' do
  title 'The VMware Cloud Foundation vCenter Server must manage excess capacity, bandwidth, or other redundancy to limit the effects of information flooding types of denial-of-service (DoS) attacks by enabling Network I/O Control (NIOC).'
  desc  "
    DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

    Managing excess capacity ensures sufficient capacity is available to counter flooding attacks. Employing increased capacity and service redundancy may reduce the susceptibility to some DoS attacks. Managing excess capacity may include, for example, establishing selected usage priorities, quotas, or partitioning.
  "
  desc  'rationale', ''
  desc  'check', "
    If distributed switches are not used, this is not applicable.

    From the vSphere Client, go to Networking.

    Select a distributed switch >> Configure >> Settings >> Properties.

    View the \"Properties\" pane and verify \"Network I/O Control\" is \"Enabled\".

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following command:

    Get-VDSwitch | select Name,@{N=\"NIOC Enabled\";E={$_.ExtensionData.config.NetworkResourceManagementEnabled}}

    If \"Network I/O Control\" is disabled, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Networking.

    Select a distributed switch >> Configure >> Settings >> Properties.

    In the \"Properties\" pane, click \"Edit\". Change \"Network I/O Control\" to \"Enabled\". Click \"OK\".

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following command:

    (Get-VDSwitch \"VDSwitch Name\" | Get-View).EnableNetworkResourceManagement($true)
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000247'
  tag satisfies: ['SRG-APP-000435']
  tag gid: 'V-VCFA-9X-000105'
  tag rid: 'SV-VCFA-9X-000105'
  tag stig_id: 'VCFA-9X-000105'
  tag cci: ['CCI-001095', 'CCI-002385']
  tag nist: ['SC-5 (2)', 'SC-5 a']

  command = 'Get-VDSwitch | Select -ExpandProperty Name'
  vdswitches = powercli_command(command).stdout.gsub("\r\n", "\n").split("\n")

  if vdswitches.blank?
    impact 0.0
    describe 'No distributed switches found to audit. This is not applicable.' do
      skip 'No distributed switches found to audit. This is not applicable.'
    end
  else
    vdswitches.each do |vds|
      command = "(Get-VDSwitch -Name \"#{vds}\").ExtensionData.Config | Select-Object NetworkResourceManagementEnabled | ConvertTo-Json -Depth 2 -WarningAction SilentlyContinue"
      result = powercli_command(command).stdout.strip

      if result.blank?
        describe "No results returned from command: #{command} . Troubleshoot issue and rerun scan." do
          skip "No results returned from command: #{command} . Troubleshoot issue and rerun scan."
        end
      else
        describe "The distributed switch with name: #{vds} and setting" do
          subject { json(content: result) }
          its(['NetworkResourceManagementEnabled']) { should cmp 'true' }
        end
      end
    end
  end
end
