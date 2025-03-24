control 'ESXI-80-000113' do
  title "The ESXi host must allocate audit record storage capacity to store at least one week's worth of audit records."
  desc 'In order to ensure ESXi has sufficient storage capacity in which to write the audit logs, audit record storage capacity should be configured.

If a central audit record storage facility is available, the local storage capacity should be sufficient to hold audit records that would accumulate during anticipated interruptions in delivery of records to the facility.'
  desc 'check', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Select the "Syslog.global.auditRecord.storageCapacity" value and verify it is set to "100".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name Syslog.global.auditRecord.storageCapacity

If the "Syslog.global.auditRecord.storageCapacity" setting is not set to 100, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Click "Edit". Select the "Syslog.global.auditRecord.storageCapacity" value and configure it to "100".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name Syslog.global.auditRecord.storageCapacity | Set-AdvancedSetting -Value 100'
  impact 0.5
  tag check_id: 'C-62483r933288_chk'
  tag severity: 'medium'
  tag gid: 'V-258743'
  tag rid: 'SV-258743r958752_rule'
  tag stig_id: 'ESXI-80-000113'
  tag gtitle: 'SRG-OS-000341-VMM-001220'
  tag fix_id: 'F-62392r933289_fix'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']

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
      command = "Get-VMHost -Name #{vmhost} | Get-AdvancedSetting -Name Syslog.global.auditRecord.storageCapacity | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp '100' }
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
