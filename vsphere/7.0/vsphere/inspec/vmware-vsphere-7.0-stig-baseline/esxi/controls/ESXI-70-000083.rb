control 'ESXI-70-000083' do
  title 'The ESXi host OpenSLP service must be disabled.'
  desc  "
    OpenSLP implements the Service Location Protocol to help CIM clients discover CIM servers over TCP 427. This service is not widely needed and has had vulnerabilities exposed in the past. In order to reduce attack surface area and following the minimum functionality principal, the OpenSLP service must be disabled unless explicitly needed and approved.

    Note: Disabling the OpenSLP service may affect monitoring and third-party systems that use the WBEM DTMF protocols.
  "
  desc  'rationale', ''
  desc  'check', "
    Fom the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >> Configure >> System >> Services.

    Locate the \"slpd\" service and verify that the \"Daemon\" is \"Stopped\" and the \"Startup Policy\" is set to \"Start and stop manually\".

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following command:

    Get-VMHost | Get-VMHostService | Where {$_.Label -eq \"slpd\"}

    If the slpd service does not have a \"Policy\" of \"off\" or is running, this is a finding.
  "
  desc  'fix', "
    Fom the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >> Configure >> System >> Services.

    Select the \"slpd\" service. If the service is started, click \"Stop\". Click \"Edit Startup Policy...\". Select \"Start and stop manually\". Click \"OK\".

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following command(s):

    Get-VMHost | Get-VMHostService | Where {$_.Label -eq \"slpd\"} | Set-VMHostService -Policy Off
    Get-VMHost | Get-VMHostService | Where {$_.Label -eq \"slpd\"} | Stop-VMHostService
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000083'
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
      command = "Get-VMHost -Name #{vmhost} | Get-VMHostService | Where {$_.Label -eq 'slpd'} | Select-Object -ExpandProperty Policy"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'off' }
      end
      command = "Get-VMHost -Name #{vmhost} | Get-VMHostService | Where {$_.Label -eq 'slpd'} | Select-Object -ExpandProperty Running"
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
