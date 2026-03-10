control 'VCFE-9X-000111' do
  title 'The ESX host must off-load audit records onto a different system or media than the system being audited.'
  desc  "
    ESX offers both local and remote audit recordkeeping to meet the requirements of the NIAP Virtualization Protection Profile and Server Virtualization Extended Package. Local records are stored on any accessible local or VMFS path. Remote records are sent to the global syslog servers configured elsewhere.

    To operate in the NIAP-validated state, ESX must enable and properly configure this audit system. This system is disabled by default.

    Note: Audit records can be viewed locally via the \"/bin/viewAudit\" utility over SSH or at the ESX shell.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Advanced System Settings.

    Select the \"Syslog.global.auditRecord.remoteEnable\" value and verify it is set to \"true\".

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name Syslog.global.auditRecord.remoteEnable

    If the \"Syslog.global.auditRecord.remoteEnable\" setting is not set to \"true\", this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Advanced System Settings.

    Click \"Edit\". Select the \"Syslog.global.auditRecord.remoteEnable\" value and configure it to \"true\".

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name Syslog.global.auditRecord.remoteEnable | Set-AdvancedSetting -Value \"true\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000342-VMM-001230'
  tag gid: 'V-VCFE-9X-000111'
  tag rid: 'SV-VCFE-9X-000111'
  tag stig_id: 'VCFE-9X-000111'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']

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
      command = "Get-VMHost -Name #{vmhost} | Get-AdvancedSetting -Name Syslog.global.auditRecord.remoteEnable | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'true' }
      end
    end
  end
end
