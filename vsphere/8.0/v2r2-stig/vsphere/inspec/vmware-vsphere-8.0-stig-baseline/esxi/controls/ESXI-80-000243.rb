control 'ESXI-80-000243' do
  title 'The ESXi host must configure a persistent log location for all locally stored logs.'
  desc %q(ESXi can be configured to store log files on an in-memory file system. This occurs when the host's "/scratch" directory is linked to "/tmp/scratch". When this is done, only a single day's worth of logs are stored at any time. In addition, log files will be reinitialized upon each reboot.

This presents a security risk as user activity logged on the host is only stored temporarily and will not persist across reboots. This can also complicate auditing and make it harder to monitor events and diagnose issues. ESXi host logging should always be configured to a persistent datastore.

Note: Scratch space is configured automatically during installation or first boot of an ESXi host and does not usually need to be configured manually.

If ESXi is installed on an SD card or USB device, a persistent log location may not be configured upon install as normal.)
  desc 'check', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Select the "Syslog.global.logDir" value and verify it is set to a persistent location.

If the value of the setting is "[] /scratch/logs", verify the advanced setting "ScratchConfig.CurrentScratchLocation" is not set to "/tmp/scratch". This is a nonpersistent location.

If "Syslog.global.logDir" is not configured to a persistent location, this is a finding.

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$esxcli = Get-EsxCli -v2
$esxcli.system.syslog.config.get.Invoke() | Select LocalLogOutput,LocalLogOutputIsPersistent

If the "LocalLogOutputIsPersistent" value is not true, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Click "Edit". Select the "Syslog.global.logDir" value and set it to a known persistent location.

An example is shown below, where 51dda02d-fade5016-8a08-005056171889 is the UUID of the target datastore:

/vmfs/volumes/51dda02d-fade5016-8a08-005056171889

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logDir | Set-AdvancedSetting -Value "New Log Location"

Note: The new location should not include a subfolder as enabling audit logging will create a folder and will fail if a subfolder is specified.'
  impact 0.5
  tag check_id: 'C-62537r933450_chk'
  tag severity: 'medium'
  tag gid: 'V-258797'
  tag rid: 'SV-258797r1003575_rule'
  tag stig_id: 'ESXI-80-000243'
  tag gtitle: 'SRG-OS-000341-VMM-001220'
  tag fix_id: 'F-62446r1003544_fix'
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
      command = "$vmhost = Get-VMHost -Name #{vmhost}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.system.syslog.config.get.Invoke() | Select-Object -ExpandProperty LocalLogOutputIsPersistent"
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
