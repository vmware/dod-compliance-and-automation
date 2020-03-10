control "ESXI-67-000022" do
  title "The ESXi host SSH daemon must be configured to not allow gateway
ports."
  desc  "SSH TCP connection forwarding provides a mechanism to establish TCP
connections proxied by the SSH server. This function can provide similar
convenience to a Virtual Private Network (VPN) with the similar risk of
providing a path to circumvent firewalls and network ACLs. Gateway ports allow
remote forwarded ports to bind to non-loopback addresses on the server."
  impact 0.3
  tag severity: "CAT III"
  tag gtitle: "SRG-OS-000480-VMM-002000"
  tag rid: "ESXI-67-000022"
  tag stig_id: "ESXI-67-000022"
  tag cci: "CCI-000366"
  tag nist: ["CM-6 b", "Rev_4"]
  desc 'check', "From an SSH session connected to the ESXi host, or from the ESXi
shell, run the following command:

# grep -i \"^GatewayPorts\" /etc/ssh/sshd_config

If there is no output or the output is not exactly \"GatewayPorts no\", this is
a finding."
  desc 'fix', "From an SSH session connected to the ESXi host, or from the ESXi
shell, add or correct the following line in \"/etc/ssh/sshd_config\":

GatewayPorts no"

  command = "$vmhost = Get-VMHost -Name #{input('vmhostName')}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq '#{input('dodStigVibRootEnabled')}' -or $_.Name -eq '#{input('dodStigVibRootDisabled')}'}"
  describe powercli_command(command) do
    its('stdout.strip') { should_not cmp "" }
  end

end

