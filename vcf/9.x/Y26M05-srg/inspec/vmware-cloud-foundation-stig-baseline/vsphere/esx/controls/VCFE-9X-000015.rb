control 'VCFE-9X-000015' do
  title 'The ESX host must produce audit records containing information to establish what type of events occurred.'
  desc  "
    Without establishing what types of events occurred, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

    Audit record content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process/VM identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

    Associating event types with detected events in the VMM audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured VMM.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Advanced System Settings.

    Select the \"Config.HostAgent.log.level\" value and verify it is set to \"info\".

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.log.level

    If the \"Config.HostAgent.log.level\" setting is not set to \"info\", this is a finding.

    Note: Verbose logging level is acceptable for troubleshooting purposes.
  "
  desc 'fix', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Advanced System Settings.

    Click \"Edit\". Select the \"Config.HostAgent.log.level\" value and configure it to \"info\".

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.log.level | Set-AdvancedSetting -Value \"info\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000037-VMM-000150'
  tag satisfies: ['SRG-OS-000063-VMM-000310']
  tag gid: 'V-VCFE-9X-000015'
  tag rid: 'SV-VCFE-9X-000015'
  tag stig_id: 'VCFE-9X-000015'
  tag cci: ['CCI-000130', 'CCI-000171']
  tag nist: ['AU-12 b', 'AU-3 a']

  vmhostName = input('esx_vmhostName')
  cluster = input('esx_cluster')
  allhosts = input('esx_allHosts')
  vmhosts = []

  unless vmhostName.blank?
    vmhosts = powercli_command("Get-VMHost -Name #{vmhostName} | Sort-Object Name | Select -ExpandProperty Name").stdout.gsub("\r\n", "\n").split("\n")
  end
  unless cluster.blank?
    vmhosts = powercli_command("Get-Cluster -Name '#{cluster}' | Get-VMHost | Sort-Object Name | Select -ExpandProperty Name").stdout.gsub("\r\n", "\n").split("\n")
  end
  unless allhosts == false
    vmhosts = powercli_command('Get-VMHost | Sort-Object Name | Select -ExpandProperty Name').stdout.gsub("\r\n", "\n").split("\n")
  end

  if vmhosts.blank?
    describe 'No ESX hosts found by name or in target vCenter...skipping test. Troubleshoot issue and rerun scan.' do
      skip 'No ESX hosts found by name or in target vCenter...skipping test. Troubleshoot issue and rerun scan.'
    end
  else
    vmhosts.each do |vmhost|
      command = "Get-VMHost -Name #{vmhost} | Get-AdvancedSetting -Name Config.HostAgent.log.level | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'info' }
      end
    end
  end
end
