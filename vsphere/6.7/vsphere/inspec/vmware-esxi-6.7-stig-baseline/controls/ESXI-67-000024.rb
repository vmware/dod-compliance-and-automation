control "ESXI-67-000024" do
  title "The ESXi host SSH daemon must not accept environment variables from
the client."
  desc  "Environment variables can be used to change the behavior of remote
sessions and should be limited. Locale environment variables that specify the
language, character set, and other features modifying the operation of software
to match the user's preferences."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000480-VMM-002000"
  tag rid: "ESXI-67-000024"
  tag stig_id: "ESXI-67-000024"
  tag cci: "CCI-000366"
  tag nist: ["CM-6 b", "Rev_4"]
  desc 'check', "From an SSH session connected to the ESXi host, or from the ESXi
shell, run the following command:

# grep -i \"^AcceptEnv\" /etc/ssh/sshd_config

If there is no output or the output is not exactly \"AcceptEnv\", this is a
finding."
  desc 'fix', "From an SSH session connected to the ESXi host, or from the ESXi
shell, add or correct the following line in \"/etc/ssh/sshd_config\":

AcceptEnv"

  command = "$vmhost = Get-VMHost -Name #{input('vmhostName')}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq '#{input('dodStigVibRootEnabled')}' -or $_.Name -eq '#{input('dodStigVibRootDisabled')}'}"
  describe powercli_command(command) do
    its('stdout.strip') { should_not cmp "" }
  end

end

