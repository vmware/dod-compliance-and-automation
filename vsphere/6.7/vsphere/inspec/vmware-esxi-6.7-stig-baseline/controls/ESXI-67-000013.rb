control 'ESXI-67-000013' do
  title 'The ESXi host SSH daemon must not allow host-based authentication.'
  desc  "SSH trust relationships mean a compromise on one host can allow an
attacker to move trivially to other hosts. SSH's cryptographic host-based
authentication is more secure than \".rhosts\" authentication, since hosts are
cryptographically authenticated. However, it is not recommended that hosts
unilaterally trust one another, even within an organization."
  desc  'rationale', ''
  desc  'check', "
    From an SSH session connected to the ESXi host, or from the ESXi shell, run
the following command:

    # grep -i \"^HostbasedAuthentication\" /etc/ssh/sshd_config

    If there is no output or the output is not exactly
\"HostbasedAuthentication no\", this is a finding.
  "
  desc 'fix', "
    From an SSH session connected to the ESXi host, or from the ESXi shell, add
or correct the following line in \"/etc/ssh/sshd_config\":

    Add or correct the following line in \"/etc/ssh/sshd_config\":

    HostbasedAuthentication no
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-239269'
  tag rid: 'SV-239269r674736_rule'
  tag stig_id: 'ESXI-67-000013'
  tag fix_id: 'F-42461r674735_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  command = "$vmhost = Get-VMHost -Name #{input('vmhostName')}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq '#{input('dodStigVibRootEnabled')}' -or $_.Name -eq '#{input('dodStigVibRootDisabled')}'}"
  describe powercli_command(command) do
    its('stdout.strip') { should_not cmp '' }
  end
end
