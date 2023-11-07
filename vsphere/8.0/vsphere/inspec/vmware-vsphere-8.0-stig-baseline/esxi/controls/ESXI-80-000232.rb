control 'ESXI-80-000232' do
  title 'The ESXi host must enable audit logging.'
  desc 'ESXi offers both local and remote audit recordkeeping to meet the requirements of the NIAP Virtualization Protection Profile and Server Virtualization Extended Package. Local records are stored on any accessible local or VMFS path. Remote records are sent to the global syslog servers configured elsewhere.

To operate in the NIAP validated state, ESXi must enable and properly configure this audit system. This system is disabled by default.

Note: Audit records can be viewed locally via the "/bin/viewAudit" utility over SSH or at the ESXi shell.'
  desc 'check', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Select the "Syslog.global.auditRecord.storageEnable" value and verify it is set to "true".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name Syslog.global.auditRecord.storageEnable

If the "Syslog.global.auditRecord.storageEnable" setting is not set to "true", this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Click "Edit". Select the "Syslog.global.auditRecord.storageEnable" value and configure it to "true".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name Syslog.global.auditRecord.storageEnable | Set-AdvancedSetting -Value "true"'
  impact 0.5
  tag check_id: 'C-62527r933420_chk'
  tag severity: 'medium'
  tag gid: 'V-258787'
  tag rid: 'SV-258787r933422_rule'
  tag stig_id: 'ESXI-80-000232'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-62436r933421_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

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
      command = "Get-VMHost -Name #{vmhost} | Get-AdvancedSetting -Name Syslog.global.auditRecord.storageEnable | Select-Object -ExpandProperty Value"
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
