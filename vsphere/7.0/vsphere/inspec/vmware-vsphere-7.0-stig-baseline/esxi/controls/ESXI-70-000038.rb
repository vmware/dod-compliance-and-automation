control 'ESXI-70-000038' do
  title 'ESXi hosts using Host Profiles and/or Auto Deploy must use the vSphere Authentication Proxy to protect passwords when adding themselves to Active Directory.'
  desc  'If a host is configured to join an Active Directory domain using Host Profiles and/or Auto Deploy, the Active Directory credentials are saved in the profile and are transmitted over the network. To avoid having to save Active Directory credentials in the Host Profile and to avoid transmitting Active Directory credentials over the network, use the vSphere Authentication Proxy.'
  desc  'rationale', ''
  desc  'check', "
    If you are not using Host Profiles to join Active Directory, this is Not Applicable.

    From the vSphere Client go to Home >> Policies and Profiles >> Host Profiles >> Click a Host Profile to details edit mode >> Configure >> Security and Services >> Security Settings >> Authentication Configuration >> Active Directory Configuration >> Join Domain Method.

    If the method used to join hosts to a domain is not set to \"Use vSphere Authentication Proxy to add the host to domain\", this is a finding.

    or

    From a PowerCLI command prompt while connected to vCenter, run the following command:

    Get-VMHost | Select Name, ` @{N=\"HostProfile\";E={$_ | Get-VMHostProfile}}, ` @{N=\"JoinADEnabled\";E={($_ | Get-VmHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory.Enabled}}, ` @{N=\"JoinDomainMethod\";E={(($_ | Get-VMHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory | Select -ExpandProperty Policy | Where {$_.Id -eq \"JoinDomainMethodPolicy\"}).Policyoption.Id}}

    If \"JoinADEnabled\" is \"True\" and \"JoinDomainMethod\" is not \"FixedCAMConfigOption\", this is a finding.
  "
  desc 'fix', "
    From the vSphere Client go to Home >> Policies and Profiles >> Host Profiles >> Click a Host Profile to enter details mode >> Configure >> Security and Services >> Security Settings >> Authentication Configuration >> Active Directory Configuration.

    Click \"Edit Host Profile...\". Set the \"Join Domain Method\" to \"Use vSphere Authentication Proxy to add the host to domain\" and provide the IP address of the vSphere Authentication Proxy server. Click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000104-VMM-000500'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000038'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']

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
      command = "Get-VMHost -Name #{vmhost} | Get-VMHostProfile"
      hostprofile = powercli_command(command).stdout

      if hostprofile.empty?
        describe '' do
          skip 'There are no attached host profiles to this host so this control is not applicable'
        end
      else
        command1 = "(Get-VMHost -Name #{vmhost} | Get-VMHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory.Enabled"
        adEnabled = powercli_command(command1).stdout.strip

        if adEnabled.match?('True')
          command2 = "(Get-VMHost -Name #{vmhost} | Get-VMHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory | Select-Object -ExpandProperty Policy | Where {$_.Id -eq 'JoinDomainMethodPolicy'} | Select-Object -ExpandProperty PolicyOption | Select-Object -ExpandProperty Id"
          describe powercli_command(command2) do
            its('stdout.strip') { should cmp 'FixedCAMConfigOption' }
          end
        else
          describe '' do
            skip 'Active Directory is not enabled on this host so this control is not applicable'
          end
        end
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
