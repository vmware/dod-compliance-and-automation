control 'ESXI-67-000038' do
  title "ESXi hosts using Host Profiles and/or Auto Deploy must use the vSphere
Authentication Proxy to protect passwords when adding themselves to Active
Directory."
  desc  "If a host is configured to join an Active Directory domain using Host
Profiles and/or Auto Deploy, the Active Directory credentials are saved in the
profile and are transmitted over the network. To avoid having to save Active
Directory credentials in the Host Profile and to avoid transmitting Active
Directory credentials over the network, use the vSphere Authentication Proxy.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Home >> Host Profiles and select a Host
Profile to edit.

    View the settings under Security and Services >> Security Settings >>
Authentication Configuration >> Active Directory Configuration >> Join Domain
Method.

    Verify the method used to join hosts to a domain is set to \"Use vSphere
Authentication Proxy to add the host to domain\".

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the
following command:

    Get-VMHost | Select Name, ` @{N=\"HostProfile\";E={$_ |
Get-VMHostProfile}}, ` @{N=\"JoinADEnabled\";E={($_ |
Get-VmHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory.Enabled}},
` @{N=\"JoinDomainMethod\";E={(($_ |
Get-VMHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory
| Select -ExpandProperty Policy | Where {$_.Id -eq
\"JoinDomainMethodPolicy\"}).Policyoption.Id}}

    Verify that if \"JoinADEnabled\" is \"True\", \"JoinDomainMethod\" is
\"FixedCAMConfigOption\".

    If not using Host Profiles to join active directory, this is not a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Home >> Host Profiles and select a Host
Profile to edit.

    View the settings under Security and Services >> Security Settings >>
Authentication Configuration >> Active Directory Configuration >> Join Domain
Method.

    Set the method used to join hosts to a domain to \"Use vSphere
Authentication Proxy to add the host to domain\" and provide the IP address of
the vSphere Authentication Proxy server.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000104-VMM-000500'
  tag satisfies: ['SRG-OS-000104-VMM-000500', 'SRG-OS-000109-VMM-000550',
'SRG-OS-000112-VMM-000560', 'SRG-OS-000113-VMM-000570']
  tag gid: 'V-239293'
  tag rid: 'SV-239293r816572_rule'
  tag stig_id: 'ESXI-67-000038'
  tag fix_id: 'F-42485r674807_fix'
  tag cci: ['CCI-000764', 'CCI-000770', 'CCI-001941', 'CCI-001942']
  tag nist: ['IA-2', 'IA-2 (5)', 'IA-2 (8)', 'IA-2 (9)']

  command = "(Get-VMHost -Name #{input('vmhostName')}) | Get-VMHostProfile"
  hostprofile = powercli_command(command).stdout

  if hostprofile.empty?
    describe '' do
      skip 'There are no attached host profiles to this host so this control is not applicable'
    end
  end

  unless hostprofile.empty?
    command1 = "(Get-VMHost -Name #{input('vmhostName')} | Get-VMHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory.Enabled"
    adEnabled = powercli_command(command1).stdout.strip

    if adEnabled.match?('True')
      command2 = "(Get-VMHost -Name #{input('vmhostName')} | Get-VMHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory | Select-Object -ExpandProperty Policy | Where {$_.Id -eq 'JoinDomainMethodPolicy'} | Select-Object -ExpandProperty PolicyOption | Select-Object -ExpandProperty Id"
      describe powercli_command(command2) do
        its('stdout.strip') { should cmp 'FixedCAMConfigOption' }
      end
    end

    if adEnabled.match?('False')
      describe '' do
        skip 'Active Directory is not enabled on this host so this control is not applicable'
      end
    end

  end
end
