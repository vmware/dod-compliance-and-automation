control 'ESXI-70-000097' do
  title 'The ESXi CIM service must be disabled.'
  desc  "
    The Common Information Model (CIM) system provides an interface that enables hardware-level management from remote applications via a set of standard APIs. These APIs are consumed by external applications such as HP SIM or Dell OpenManage for agentless, remote hardware monitoring of the ESXi host.

    In order to reduce attack surface area and following the minimum functionality principal, the CIM service must be disabled unless explicitly needed and approved.
  "
  desc  'rationale', ''
  desc  'check', "
    Fom the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >> Configure >> System >> Services.

    Locate the \"CIM Server\" service and verify that the \"Daemon\" is \"Stopped\" and the \"Startup Policy\" is set to \"Start and stop manually\".

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following command:

    Get-VMHost | Get-VMHostService | Where {$_.Label -eq \"CIM Server\"}

    If the slpd service does not have a \"Policy\" of \"off\" or is running, this is a finding.
  "
  desc  'fix', "
    Fom the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >> Configure >> System >> Services.

    Select the \"CIM Server\" service. If the service is started, click \"Stop\". Click \"Edit Startup Policy...\". Select \"Start and stop manually\". Click \"OK\".

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following command(s):

    Get-VMHost | Get-VMHostService | Where {$_.Label -eq \"CIM Server\"} | Set-VMHostService -Policy Off
    Get-VMHost | Get-VMHostService | Where {$_.Label -eq \"CIM Server\"} | Stop-VMHostService
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000097'
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
      command = "Get-VMHost -Name #{vmhost} | Get-VMHostService | Where {$_.Label -eq 'CIM Server'} | Select-Object -ExpandProperty Policy"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'off' }
      end
      command = "Get-VMHost -Name #{vmhost} | Get-VMHostService | Where {$_.Label -eq 'CIM Server'} | Select-Object -ExpandProperty Running"
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
