control 'ESXI-80-000201' do
  title 'The ESXi host lockdown mode exception users list must be verified.'
  desc 'While a host is in lockdown mode (strict or normal), only users on the "Exception Users" list are allowed access. These users do not lose their permissions when the host enters lockdown mode.

The organization may want to add service accounts such as a backup agent to the Exception Users list. Verify the list of users exempted from losing permissions is legitimate and as needed per the environment. Adding unnecessary users to the exception list defeats the purpose of lockdown mode.'
  desc 'check', 'For environments that do not use vCenter server to manage ESXi, this is not applicable.

From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Security Profile.

Under "Lockdown Mode", review the Exception Users list.

or

From a PowerCLI command prompt while connected to the ESXi host, run the following script:

$vmhost = Get-VMHost | Get-View
$lockdown = Get-View $vmhost.ConfigManager.HostAccessManager
$lockdown.QueryLockdownExceptions()

If the Exception Users list contains accounts that do not require special permissions, this is a finding.

Note: The Exception Users list is empty by default and should remain that way except under site-specific circumstances.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Security Profile.

Under "Lockdown Mode", click "Edit" and remove unnecessary users from the Exception Users list.'
  impact 0.5
  tag check_id: 'C-62500r933339_chk'
  tag severity: 'medium'
  tag gid: 'V-258760'
  tag rid: 'SV-258760r933341_rule'
  tag stig_id: 'ESXI-80-000201'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-62409r933340_fix'
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
      command = "$vmhost = Get-VMHost -Name #{vmhost} | Get-View; (Get-View $vmhost.ConfigManager.HostAccessManager).QueryLockdownExceptions()"
      results = powercli_command(command).stdout
      if !results.empty?
        results.split.each do |exceptionUser|
          describe "Exception user: #{exceptionUser} on host: #{vmhost}" do
            subject { exceptionUser }
            it { should be_in "#{input('exceptionUsers')}" }
          end
        end
      else
        describe "Exception users for host: #{vmhost}" do
          subject { results }
          it { should be_empty }
        end
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
