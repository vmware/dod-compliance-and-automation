control 'ESXI-67-000015' do
  title "The ESXi host SSH daemon must not allow authentication using an empty
password."
  desc  "Configuring this setting for the SSH daemon provides additional
assurance that remote logon via SSH will require a password, even in the event
of misconfiguration elsewhere."
  desc  'rationale', ''
  desc  'check', "
    From an SSH session connected to the ESXi host, or from the ESXi shell, run
the following command:

    # grep -i \"^PermitEmptyPasswords\" /etc/ssh/sshd_config

    If there is no output or the output is not exactly \"PermitEmptyPasswords
no\", this is a finding.
  "
  desc 'fix', "
    From an SSH session connected to the ESXi host, or from the ESXi shell, add
or correct the following line in \"/etc/ssh/sshd_config\":

    PermitEmptyPasswords no
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-239271'
  tag rid: 'SV-239271r674742_rule'
  tag stig_id: 'ESXI-67-000015'
  tag fix_id: 'F-42463r674741_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  command = "$vmhost = Get-VMHost -Name #{input('vmhostName')}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq '#{input('dodStigVibRootEnabled')}' -or $_.Name -eq '#{input('dodStigVibRootDisabled')}'}"
  describe powercli_command(command) do
    its('stdout.strip') { should_not cmp '' }
  end
end
