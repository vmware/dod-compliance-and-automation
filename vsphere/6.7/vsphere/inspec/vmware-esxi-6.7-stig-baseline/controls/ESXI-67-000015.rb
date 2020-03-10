control "ESXI-67-000015" do
  title "The ESXi host SSH daemon must not allow authentication using an empty
password."
  desc  "Configuring this setting for the SSH daemon provides additional
assurance that remote login via SSH will require a password, even in the event
of misconfiguration elsewhere."
  impact 1.0
  tag severity: "CAT I"
  tag gtitle: "SRG-OS-000480-VMM-002000"
  tag rid: "ESXI-67-000015"
  tag stig_id: "ESXI-67-000015"
  tag cci: "CCI-000366"
  tag nist: ["CM-6 b", "Rev_4"]
  desc 'check', "From an SSH session connected to the ESXi host, or from the ESXi
shell, run the following command:

# grep -i \"^PermitEmptyPasswords\" /etc/ssh/sshd_config

If there is no output or the output is not exactly \"PermitEmptyPasswords no\",
this is a finding."
  desc 'fix', "From an SSH session connected to the ESXi host, or from the ESXi
shell, add or correct the following line in \"/etc/ssh/sshd_config\":

PermitEmptyPasswords no"

  command = "$vmhost = Get-VMHost -Name #{input('vmhostName')}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq '#{input('dodStigVibRootEnabled')}' -or $_.Name -eq '#{input('dodStigVibRootDisabled')}'}"
  describe powercli_command(command) do
    its('stdout.strip') { should_not cmp "" }
  end

end

