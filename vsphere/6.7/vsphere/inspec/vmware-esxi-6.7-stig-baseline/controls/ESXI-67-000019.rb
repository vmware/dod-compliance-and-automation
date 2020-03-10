control "ESXI-67-000019" do
  title "The ESXi host SSH daemon must not permit Kerberos authentication."
  desc  "Kerberos authentication for SSH is often implemented using GSSAPI.  If
Kerberos is enabled through SSH, the SSH daemon provides a means of access to
the system's Kerberos implementation.  Vulnerabilities in the system's Kerberos
implementation may then be subject to exploitation.  To reduce the attack
surface of the system, the Kerberos authentication mechanism within SSH must be
disabled for systems."
  impact 0.3
  tag severity: "CAT III"
  tag gtitle: "SRG-OS-000480-VMM-002000"
  tag rid: "ESXI-67-000019"
  tag stig_id: "ESXI-67-000019"
  tag cci: "CCI-000366"
  tag nist: ["CM-6 b", "Rev_4"]
  desc 'check', "From an SSH session connected to the ESXi host, or from the ESXi
shell, run the following command:

# grep -i \"^KerberosAuthentication\" /etc/ssh/sshd_config

If there is no output or the output is not exactly \"KerberosAuthentication
no\", this is a finding."
  desc 'fix', "From an SSH session connected to the ESXi host, or from the ESXi
shell, add or correct the following line in \"/etc/ssh/sshd_config\":

KerberosAuthentication no"

  command = "$vmhost = Get-VMHost -Name #{input('vmhostName')}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq '#{input('dodStigVibRootEnabled')}' -or $_.Name -eq '#{input('dodStigVibRootDisabled')}'}"
  describe powercli_command(command) do
    its('stdout.strip') { should_not cmp "" }
  end

end

