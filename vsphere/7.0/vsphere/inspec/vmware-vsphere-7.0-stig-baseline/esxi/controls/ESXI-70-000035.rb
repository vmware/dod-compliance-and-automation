control 'ESXI-70-000035' do
  title 'The ESXi host must be configured to disable nonessential capabilities by disabling SSH.'
  desc  "
    The ESXi Shell is an interactive command line interface (CLI) available at the ESXi server console. The ESXi shell provides temporary access to commands essential for server maintenance. Intended primarily for use in break-fix scenarios, the ESXi shell is well suited for checking and modifying configuration details, not always generally accessible, using the vSphere Client.

    The ESXi shell is accessible remotely using SSH by users with the Administrator role. Under normal operating conditions, SSH access to the host must be disabled as is the default. As with the ESXi shell, SSH is also intended only for temporary use during break-fix scenarios. SSH must therefore be disabled under normal operating conditions and must only be enabled for diagnostics or troubleshooting. Remote access to the host must therefore be limited to the vSphere Client or Host Client at all other times.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >> Configure >> System >> Services.

    Under Services, locate the \"SSH\" service and verify it is \"Stopped\".

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following command:

    Get-VMHost | Get-VMHostService | Where {$_.Label -eq \"SSH\"}

    If the SSH service is \"Running\", this is a finding.
  "
  desc 'fix', "
    From the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >> Configure >> System >> Services.

    Under Services select the \"SSH\" service and click the \"Stop\" button. Click the \"Edit Startup policy...\" button. Select the \"Start and stop manually\" radio button. Click \"OK\".

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following command(s):

    Get-VMHost | Get-VMHostService | Where {$_.Label -eq \"SSH\"} | Set-VMHostService -Policy Off
    Get-VMHost | Get-VMHostService | Where {$_.Label -eq \"SSH\"} | Stop-VMHostService
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000095-VMM-000480'
  tag satisfies: ['SRG-OS-000297-VMM-001040', 'SRG-OS-000298-VMM-001050']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000035'
  tag cci: ['CCI-000381', 'CCI-002314', 'CCI-002322']
  tag nist: ['AC-17 (1)', 'AC-17 (9)', 'CM-7 a']

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
      command = "Get-VMHost -Name #{vmhost} | Get-VMHostService | Where {$_.Label -eq 'SSH'} | Select-Object -ExpandProperty Policy"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'off' }
      end
      command = "Get-VMHost -Name #{vmhost} | Get-VMHostService | Where {$_.Label -eq 'SSH'} | Select-Object -ExpandProperty Running"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'false' }
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
