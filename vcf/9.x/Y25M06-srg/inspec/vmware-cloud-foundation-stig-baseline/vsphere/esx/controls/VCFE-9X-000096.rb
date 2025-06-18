control 'VCFE-9X-000096' do
  title 'The ESX host must disable remote access to the information system by disabling Secure Shell (SSH).'
  desc  "
    The ESX Shell is an interactive command line interface (CLI) available at the ESX server console. The ESX shell provides temporary access to commands essential for server maintenance. Intended primarily for use in break-fix scenarios, the ESX shell is well suited for checking and modifying configuration details, which are not always generally accessible, using the vSphere Client.

    The ESX shell is accessible remotely using SSH by users with the Administrator role. Under normal operating conditions, SSH access to the host must be disabled as is the default. As with the ESX shell, SSH is also intended only for temporary use during break-fix scenarios. SSH must therefore be disabled under normal operating conditions and must only be enabled for diagnostics or troubleshooting. Remote access to the host must therefore be limited to the vSphere Client or Host Client at all other times.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Services.

    Under Services, locate the \"SSH\" service and verify it is \"Stopped\".

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following command:

    Get-VMHost | Get-VMHostService | Where {$_.Label -eq \"SSH\"}

    If the \"SSH\" service does not have a \"Policy\" of \"off\" or is running, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Services.

    Under \"Services\", select the \"SSH\" service and click the \"Stop\" button.

    Click the \"Edit Startup policy...\" button.

    Select the \"Start and stop manually\" radio button.

    Click \"OK\".

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following commands:

    Get-VMHost | Get-VMHostService | Where {$_.Label -eq \"SSH\"} | Set-VMHostService -Policy Off
    Get-VMHost | Get-VMHostService | Where {$_.Label -eq \"SSH\"} | Stop-VMHostService
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000298-VMM-001050'
  tag satisfies: ['SRG-OS-000297-VMM-001040']
  tag gid: 'V-VCFE-9X-000096'
  tag rid: 'SV-VCFE-9X-000096'
  tag stig_id: 'VCFE-9X-000096'
  tag cci: ['CCI-002314', 'CCI-002322']
  tag nist: ['AC-17 (1)', 'AC-17 (9)']

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
      command = "Get-VMHost -Name #{vmhost} | Get-VMHostService | Where {$_.Label -eq 'SSH'} | Select-Object -ExpandProperty Policy"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'off' }
      end
      command = "Get-VMHost -Name #{vmhost} | Get-VMHostService | Where {$_.Label -eq 'SSH'} | Select-Object -ExpandProperty Running"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'false' }
      end
    end
  end
end
