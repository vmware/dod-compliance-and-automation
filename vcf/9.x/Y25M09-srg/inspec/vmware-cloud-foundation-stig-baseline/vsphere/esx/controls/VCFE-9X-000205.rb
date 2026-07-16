control 'VCFE-9X-000205' do
  title 'The ESX host lockdown mode exception users list must be verified.'
  desc  "
    While a host is in lockdown mode (strict or normal), only users on the \"Exception Users\" list are allowed access. These users do not lose their permissions when the host enters lockdown mode.

    The organization may want to add service accounts such as a backup agent to the Exception Users list. Verify the list of users exempted from losing permissions is legitimate and as needed per the environment. Adding unnecessary users to the exception list defeats the purpose of lockdown mode.
  "
  desc  'rationale', ''
  desc  'check', "
    For environments that do not use vCenter server to manage ESX, this is not applicable.

    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Security Profile.

    Under \"Lockdown Mode\", review the Exception Users list.

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following script:

    $vmhost = Get-VMHost | Get-View
    $lockdown = Get-View $vmhost.ConfigManager.HostAccessManager
    $lockdown.QueryLockdownExceptions()

    If the Exception Users list contains accounts that do not require special permissions, this is a finding.

    Note: The Exception Users list is empty by default and should remain that way except under site-specific circumstances.
  "
  desc 'fix', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Security Profile.

    Under \"Lockdown Mode\", click \"Edit\" and remove unnecessary users from the Exception Users list.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-VCFE-9X-000205'
  tag rid: 'SV-VCFE-9X-000205'
  tag stig_id: 'VCFE-9X-000205'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

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
      command = "$vmhost = Get-VMHost -Name #{vmhost} | Get-View; (Get-View $vmhost.ConfigManager.HostAccessManager).QueryLockdownExceptions()"
      results = powercli_command(command).stdout
      if !results.blank?
        results.split.each do |exceptionuser|
          describe "Exception user: #{exceptionuser} on host: #{vmhost}" do
            subject { exceptionuser }
            it { should be_in "#{input('esx_lockdownExceptionUsers')}" }
          end
        end
      else
        describe "Exception users for host: #{vmhost}" do
          subject { results }
          it { should be_blank }
        end
      end
    end
  end
end
