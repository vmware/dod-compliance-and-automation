control 'VCFE-9X-000110' do
  title "The ESX host must allocate audit record storage capacity to store at least one week's worth of audit records."
  desc  "
    In order to ensure ESX has sufficient storage capacity in which to write the audit logs, audit record storage capacity should be configured.

    If a central audit record storage facility is available, the local storage capacity should be sufficient to hold audit records that would accumulate during anticipated interruptions in delivery of records to the facility.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Advanced System Settings.

    Select the \"Syslog.global.auditRecord.storageCapacity\" value and verify it is set to \"100\".

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name Syslog.global.auditRecord.storageCapacity

    If the \"Syslog.global.auditRecord.storageCapacity\" setting is not set to 100, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Advanced System Settings.

    Click \"Edit\". Select the \"Syslog.global.auditRecord.storageCapacity\" value and configure it to \"100\".

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name Syslog.global.auditRecord.storageCapacity | Set-AdvancedSetting -Value 100
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000341-VMM-001220'
  tag gid: 'V-VCFE-9X-000110'
  tag rid: 'SV-VCFE-9X-000110'
  tag stig_id: 'VCFE-9X-000110'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']

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
      command = "Get-VMHost -Name #{vmhost} | Get-AdvancedSetting -Name Syslog.global.auditRecord.storageCapacity | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp '100' }
      end
    end
  end
end
