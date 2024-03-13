control 'ESXI-80-000008' do
  title 'The ESXi host must enable lockdown mode.'
  desc  "
    Enabling Lockdown Mode disables direct access to an ESXi host, requiring the host to be managed remotely from vCenter Server. This is done to ensure the roles and access controls implemented in vCenter are always enforced and users cannot bypass them by logging on to a host directly.

    By forcing all interaction to occur through vCenter Server, the risk of someone inadvertently attaining elevated privileges or performing tasks that are not properly audited is greatly reduced.
  "
  desc  'rationale', ''
  desc  'check', "
    For environments that do not use vCenter server to manage ESXi, this is not applicable.

    From the vSphere Client, go to Hosts and Clusters.

    Select the ESXi Host >> Configure >> System >> Security Profile.

    Scroll down to \"Lockdown Mode\" and verify it is set to \"Enabled\" (Normal or Strict).

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following command:

    Get-VMHost | Select Name,@{N=\"Lockdown\";E={$_.Extensiondata.Config.LockdownMode}}

    If \"Lockdown Mode\" is disabled, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESXi Host >> Configure >> System >> Security Profile >> Lockdown Mode.

    Click edit and select either the \"Normal\" or \"Strict\" radio buttons.

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

    $level = \"lockdownNormal\" OR \"lockdownStrict\"
    $vmhost = Get-VMHost -Name <hostname> | Get-View
    $lockdown = Get-View $vmhost.ConfigManager.HostAccessManager
    $lockdown.ChangeLockdownMode($level)

    Note: In strict lockdown mode, the Direct Console User Interface (DCUI) service is stopped. If the connection to vCenter Server is lost and the vSphere Client is no longer available, the ESXi host becomes inaccessible.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000027-VMM-000080'
  tag gid: 'V-ESXI-80-000008'
  tag rid: 'SV-ESXI-80-000008'
  tag stig_id: 'ESXI-80-000008'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']

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
