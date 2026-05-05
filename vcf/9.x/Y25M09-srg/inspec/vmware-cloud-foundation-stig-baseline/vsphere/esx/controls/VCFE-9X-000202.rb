control 'VCFE-9X-000202' do
  title 'The ESX host must configure a persistent log location for all locally stored logs and audit records.'
  desc  "
    ESX can be configured to store log files on an in-memory file system. This can occur if logs are stored in a nonpersistent location such as /tmp.

    This presents a security risk as user activity logged on the host is only stored temporarily and will not persist across reboots. This can also complicate auditing and make it harder to monitor events and diagnose issues. ESX host logging should always be configured to persistent storage.

    By default logs and audit records are stored on persistent storage under /scratch/log and /scratch/auditLog unless changed post installation.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Advanced System Settings.

    Select the \"Syslog.global.logDir\" value and verify it is set to a persistent location.

    If the value of the setting is \"[] /scratch/logs\", verify the advanced setting \"ScratchConfig.CurrentScratchLocation\" is not set to \"/tmp/scratch\". This is a nonpersistent location.

    If \"Syslog.global.logDir\" is not configured to a persistent location, this is a finding.

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following commands:

    $esxcli = Get-EsxCli -v2
    $esxcli.system.syslog.config.get.Invoke() | Select LocalLogOutput,LocalLogOutputIsPersistent

    If the \"LocalLogOutputIsPersistent\" value is not true, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Advanced System Settings.

    Click \"Edit\". Select the \"Syslog.global.logDir\" value and set it to a known persistent location.

    An example is shown below, where 51dda02d-fade5016-8a08-005056171889 is the UUID of the target datastore:

    /vmfs/volumes/51dda02d-fade5016-8a08-005056171889

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following command:

    Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logDir | Set-AdvancedSetting -Value \"New Log Location\"

    Note: The new location should not include a subfolder as enabling audit logging will create a folder and will fail if a subfolder is specified.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000341-VMM-001220'
  tag gid: 'V-VCFE-9X-000202'
  tag rid: 'SV-VCFE-9X-000202'
  tag stig_id: 'VCFE-9X-000202'
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
      command = "$vmhost = Get-VMHost -Name #{vmhost}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.system.syslog.config.get.Invoke() | Select-Object -ExpandProperty LocalLogOutputIsPersistent"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'true' }
      end
    end
  end
end
