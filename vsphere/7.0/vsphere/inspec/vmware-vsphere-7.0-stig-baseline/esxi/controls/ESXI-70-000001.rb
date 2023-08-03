control 'ESXI-70-000001' do
  title 'Access to the ESXi host must be limited by enabling lockdown mode.'
  desc 'Enabling lockdown mode disables direct access to an ESXi host, requiring the host to be managed remotely from vCenter Server. This is done to ensure the roles and access controls implemented in vCenter are always enforced and users cannot bypass them by logging on to a host directly.

By forcing all interaction to occur through vCenter Server, the risk of someone inadvertently attaining elevated privileges or performing tasks that are not properly audited is greatly reduced.

'
  desc 'check', 'For environments that do not use vCenter server to manage ESXi, this is not applicable.

From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Security Profile.

Scroll down to "Lockdown Mode" and verify it is set to "Enabled" (Normal or Strict).

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Select Name,@{N="Lockdown";E={$_.Extensiondata.Config.LockdownMode}}

If "Lockdown Mode" is disabled, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Security Profile >> Lockdown Mode.

Click "Edit...". Select the "Normal" or "Strict" radio buttons.

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$level = "lockdownNormal" OR "lockdownStrict"
$vmhost = Get-VMHost -Name <hostname> | Get-View
$lockdown = Get-View $vmhost.ConfigManager.HostAccessManager
$lockdown.ChangeLockdownMode($level)

Note: In strict lockdown mode, the Direct Console User Interface (DCUI) service is stopped. If the connection to vCenter Server is lost and the vSphere Client is no longer available, the ESXi host becomes inaccessible.'
  impact 0.5
  tag check_id: 'C-60050r885904_chk'
  tag severity: 'medium'
  tag gid: 'V-256375'
  tag rid: 'SV-256375r885906_rule'
  tag stig_id: 'ESXI-70-000001'
  tag gtitle: 'SRG-OS-000027-VMM-000080'
  tag fix_id: 'F-59993r885905_fix'
  tag satisfies: ['SRG-OS-000027-VMM-000080', 'SRG-OS-000123-VMM-000620']
  tag cci: ['CCI-000054', 'CCI-001682']
  tag nist: ['AC-10', 'AC-2 (2)']

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
    list = ['lockdownNormal', 'lockdownStrict']
    vmhosts.each do |vmhost|
      command = "(Get-VMHost -Name #{vmhost}).Extensiondata.Config.LockdownMode"
      describe powercli_command(command) do
        its('stdout.strip') { should be_in list }
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
