control 'ESXI-67-000036' do
  title "The ESXi host must disable ESXi Shell unless needed for diagnostics or
troubleshooting."
  desc  "The ESXi Shell is an interactive command line environment available
locally from the DCUI or remotely via SSH. Activities performed from the ESXi
Shell bypass vCenter RBAC and audit controls.

    The ESXi shell should only be turned on when needed to troubleshoot/resolve
problems that cannot be fixed through the vSphere client.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, select the ESXi host and go to Configure >> System
>> Services.

    Under \"Services\", select \"Edit\", view the \"ESXi Shell\" service, and
verify it is stopped.

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the
following command:

    Get-VMHost | Get-VMHostService | Where {$_.Label -eq \"ESXi Shell\"}

    If the ESXi Shell service is running, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, select the ESXi host and go to Configure >> System
>> Services.

    Under \"Services\", select \"ESXi Shell\" service and click the \"Stop\"
button to stop the service. Use Edit Startup policy to \"Start and stop
manually\" and click \"OK\".

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the
following commands:

    Get-VMHost | Get-VMHostService | Where {$_.Label -eq \"ESXi Shell\"} |
Set-VMHostService -Policy Off
    Get-VMHost | Get-VMHostService | Where {$_.Label -eq \"ESXi Shell\"} |
Stop-VMHostService
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000095-VMM-000480'
  tag gid: 'V-239291'
  tag rid: 'SV-239291r674802_rule'
  tag stig_id: 'ESXI-67-000036'
  tag fix_id: 'F-42483r674801_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  command = "(Get-VMHost -Name #{input('vmhostName')}) | Get-VMHostService | Where {$_.Label -eq 'ESXi Shell'} | Select-Object -ExpandProperty Policy"
  describe powercli_command(command) do
    its('stdout.strip') { should cmp 'off' }
  end

  command = "(Get-VMHost -Name #{input('vmhostName')}) | Get-VMHostService | Where {$_.Label -eq 'ESXi Shell'} | Select-Object -ExpandProperty Running"
  describe powercli_command(command) do
    its('stdout.strip') { should cmp 'false' }
  end
end
