control 'VCFE-9X-000199' do
  title 'The ESX host must be configured to disable nonessential capabilities by disabling the ESX shell.'
  desc  "
    The ESX Shell is an interactive command line environment available locally from the Direct Console User Interface (DCUI) or remotely via SSH. Activities performed from the ESX Shell bypass vCenter role-based access control (RBAC) and audit controls.

    The ESX shell must only be turned on when needed to troubleshoot/resolve problems that cannot be fixed through the vSphere client.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Services.

    Under Services, locate the \"ESXi Shell\" service and verify it is \"Stopped\".

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following command:

    Get-VMHost | Get-VMHostService | Where {$_.Label -eq \"ESXi Shell\"}

    If the \"ESXi Shell\" service does not have a \"Policy\" of \"off\" or is running, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Services.

    Under \"Services\", select the \"ESXi Shell\" service and click the \"Stop\" button.

    Click the \"Edit Startup policy...\" button.

    Select the \"Start and stop manually\" radio button.

    Click \"OK\".

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following commands:

    Get-VMHost | Get-VMHostService | Where {$_.Label -eq \"ESXi Shell\"} | Set-VMHostService -Policy Off
    Get-VMHost | Get-VMHostService | Where {$_.Label -eq \"ESXi Shell\"} | Stop-VMHostService
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000095-VMM-000480'
  tag gid: 'V-VCFE-9X-000199'
  tag rid: 'SV-VCFE-9X-000199'
  tag stig_id: 'VCFE-9X-000199'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

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
      command = "Get-VMHost -Name #{vmhost} | Get-VMHostService | Where {$_.Label -eq 'ESXi Shell'} | Select-Object -ExpandProperty Policy"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'off' }
      end
      command = "Get-VMHost -Name #{vmhost} | Get-VMHostService | Where {$_.Label -eq 'ESXi Shell'} | Select-Object -ExpandProperty Running"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'false' }
      end
    end
  end
end
