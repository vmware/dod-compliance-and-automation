control 'ESXI-80-000233' do
  title 'The ESXi host must off-load audit records via syslog.'
  desc  "
    ESXi offers both local and remote audit recordkeeping to meet the requirements of the NIAP Virtualization Protection Profile and Server Virtualization Extended Package. Local records are stored on any accessible local or VMFS path. Remote records are sent to the global syslog servers configured elsewhere.

    To operate in the NIAP validated state, ESXi must enable and properly configure this audit system. This system is disabled by default.

    Note: Audit records can be viewed locally via the \"/bin/viewAudit\" utility over SSH or at the ESXi shell.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESXi Host >> Configure >> System >> Advanced System Settings.

    Select the \"Syslog.global.auditRecord.remoteEnable\" value and verify it is set to \"true\".

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name Syslog.global.auditRecord.remoteEnable

    If the \"Syslog.global.auditRecord.remoteEnable\" setting is not set to \"true\", this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESXi Host >> Configure >> System >> Advanced System Settings.

    Click \"Edit\". Select the \"Syslog.global.auditRecord.remoteEnable\" value and configure it to \"true\".

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name Syslog.global.auditRecord.remoteEnable | Set-AdvancedSetting -Value \"true\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000342-VMM-001230'
  tag gid: 'V-ESXI-80-000233'
  tag rid: 'SV-ESXI-80-000233'
  tag stig_id: 'ESXI-80-000233'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']

  vmhostName = input('vmhostName')
  cluster = input('cluster')
  allhosts = input('allesxi')
  vmhosts = []

  unless vmhostName.empty?
    vmhosts = powercli_command("Get-VMHost -Name #{vmhostName} | Sort-Object Name | Select -ExpandProperty Name").stdout.split
  end
  unless cluster.empty?
    vmhosts = powercli_command("Get-Cluster -Name '#{cluster}' | Get-VMHost | Sort-Object Name | Select -ExpandProperty Name").stdout.split
  end
  unless allhosts == false
    vmhosts = powercli_command('Get-VMHost | Sort-Object Name | Select -ExpandProperty Name').stdout.split
  end

  if !vmhosts.empty?
    vmhosts.each do |vmhost|
      command = "Get-VMHost -Name #{vmhost} | Get-AdvancedSetting -Name Syslog.global.auditRecord.remoteEnable | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'true' }
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
