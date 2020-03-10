control "ESXI-67-000035" do
  title "The ESXi host must be configured to disable non-essential capabilities
by disabling SSH."
  desc  "The ESXi Shell is an interactive command line interface (CLI)
available at the ESXi server console. The ESXi shell provides temporary access
to commands essential for server maintenance. Intended primarily for use in
break-fix scenarios, the ESXi shell is well suited for checking and modifying
configuration details, not always generally accessible, using the vSphere
Client. The ESXi shell is accessible remotely using SSH by users with the
Administrator role. Under normal operating conditions, SSH access to the host
must be disabled as is the default.  As with the ESXi shell, SSH is also
intended only for temporary use during break-fix scenarios. SSH must therefore
be disabled under normal operating conditions and must only be enabled for
diagnostics or troubleshooting. Remote access to the host must therefore be
limited to the vSphere Client or Host Client at all other times."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000095-VMM-000480"
  tag rid: "ESXI-67-000035"
  tag stig_id: "ESXI-67-000035"
  tag cci: "CCI-000381"
  tag nist: ["CM-7 a", "Rev_4"]
  desc 'check', "From the vSphere Client select the ESXi Host and go to Configure
>> System >> Services. Under Services select Edit and view the \"SSH\" service
and verify it is stopped.

or

From a PowerCLI command prompt while connected to the ESXi host run the
following command:

Get-VMHost | Get-VMHostService | Where {$_.Label -eq \"SSH\"}

If the ESXi SSH service is running, this is a finding."
  desc 'fix', "From the vSphere Client select the ESXi Host and go to Configure >>
System >> Services. Under Services select SSH service and click the Stop button
to stop the service. Use Edit Startup policy to \"Start and stop manually\" and
click OK.

or

From a PowerCLI command prompt while connected to the ESXi host run the
following commands:

Get-VMHost | Get-VMHostService | Where {$_.Label -eq \"SSH\"} |
Set-VMHostService -Policy Off
Get-VMHost | Get-VMHostService | Where {$_.Label -eq \"SSH\"} |
Stop-VMHostService"

  command = "(Get-VMHost -Name #{input('vmhostName')}) | Get-VMHostService | Where {$_.Label -eq 'SSH'} | Select-Object -ExpandProperty Policy"
  describe powercli_command(command) do
    its('stdout.strip') { should cmp "off" }
  end

  command = "(Get-VMHost -Name #{input('vmhostName')}) | Get-VMHostService | Where {$_.Label -eq 'SSH'} | Select-Object -ExpandProperty Running"
  describe powercli_command(command) do
    its('stdout.strip') { should cmp "false" }
  end

end

