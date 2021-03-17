# encoding: UTF-8

control 'VCSA-70-000007' do
  title "The vCenter Server must manage excess capacity, bandwidth, or other
redundancy to limit the effects of information-flooding types of Denial of
Service (DoS) attacks by enabling Network I/O Control (NIOC)."
  desc  "DoS is a condition when a resource is not available for legitimate
users. When this occurs, the organization either cannot accomplish its mission
or must operate at degraded capacity.

    Managing excess capacity ensures that sufficient capacity is available to
counter flooding attacks. Employing increased capacity and service redundancy
may reduce the susceptibility to some DoS attacks. Managing excess capacity may
include, for example, establishing selected usage priorities, quotas, or
partitioning.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Networking >> Select a distributed switch >>
Configure >> Settings >> Properties. View the Properties pane and verify that
\"Network I/O Control\" is \"Enabled\".

    or

    From a PowerCLI command prompt while connected to the vCenter server run
the following command:

    Get-VDSwitch | select Name,@{N=\"NIOC
Enabled\";E={$_.ExtensionData.config.NetworkResourceManagementEnabled}}

    If Network I/O Control is disabled, this is a finding.
  "
  desc  'fix', "
    From the vSphere Client, go to Networking >> Select a distributed switch >>
Configure >> Settings >> Properties. In the Properties pane click \"Edit\".
Change Network I/O Control to enabled. Click \"OK\".

    or

    From a PowerCLI command prompt while connected to the vCenter server run
the following command:

    (Get-VDSwitch \"VDSwitch Name\" |
Get-View).EnableNetworkResourceManagement($true)
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCSA-70-000007'
  tag fix_id: nil
  tag cci: 'CCI-000366'
  tag nist: ['CM-6 b']

  command = "Get-VDSwitch | Select -ExpandProperty Name"
  vdswitches = powercli_command(command).stdout.strip.split("\r\n")

  if vdswitches.empty?
    describe "" do
      skip "No distributed switches found to check."
    end
  end

  if !vdswitches.empty?
    vdswitches.each do | vds |
      command = "(Get-VDSwitch -Name \"#{vds}\").ExtensionData.Config.NetworkResourceManagementEnabled"
      describe powercli_command(command) do
        its ('stdout.strip') { should cmp "true" }
      end
    end
  end

end

