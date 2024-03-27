control 'ESXI-80-000231' do
  title 'The ESXi host OpenSLP service must be disabled.'
  desc  "
    OpenSLP implements the Service Location Protocol to help CIM clients discover CIM servers over TCP 427. This service is not widely needed and has had vulnerabilities exposed in the past. To reduce attack surface area and following the minimum functionality principal, the OpenSLP service must be disabled unless explicitly needed and approved.

    Note: Disabling the OpenSLP service may affect monitoring and third-party systems that use the WBEM DTMF protocols.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client go to Hosts and Clusters.

    Select the ESXi Host >> Configure >> System >> Services.

    Under \"Services\", locate the \"slpd\" service and verify it is \"Stopped\" and the \"Startup Policy\" is set to \"Start and stop manually\".

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following command:

    Get-VMHost | Get-VMHostService | Where {$_.Label -eq \"slpd\"}

    If the slpd service does not have a \"Policy\" of \"off\" or is running, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client go to Hosts and Clusters.

    Select the ESXi Host >> Configure >> System >> Services.

    Under \"Services\" select the \"slpd\" service and click the \"Stop\" button.

    Click \"Edit Startup policy...\" and select the \"Start and stop manually\" radio button. Click \"OK\".

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

    Get-VMHost | Get-VMHostService | Where {$_.Label -eq \"slpd\"} | Set-VMHostService -Policy Off
    Get-VMHost | Get-VMHostService | Where {$_.Label -eq \"slpd\"} | Stop-VMHostService
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-ESXI-80-000231'
  tag rid: 'SV-ESXI-80-000231'
  tag stig_id: 'ESXI-80-000231'
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
