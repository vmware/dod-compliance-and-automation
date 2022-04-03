control 'ESXI-67-000012' do
  title 'The ESXi host SSH daemon must ignore .rhosts files.'
  desc  "SSH trust relationships mean a compromise on one host can allow an
attacker to move trivially to other hosts. SSH can emulate the behavior of the
obsolete rsh command in allowing users to enable insecure access to their
accounts via \".rhosts\" files."
  desc  'rationale', ''
  desc  'check', "
    From an SSH session connected to the ESXi host, or from the ESXi shell, run
the following command:

    # grep -i \"^IgnoreRhosts\" /etc/ssh/sshd_config

    If there is no output or the output is not exactly \"IgnoreRhosts yes\",
this is a finding.
  "
  desc 'fix', "
    From an SSH session connected to the ESXi host, or from the ESXi shell, add
or correct the following line in \"/etc/ssh/sshd_config\":

    Add or correct the following line in \"/etc/ssh/sshd_config\":

    IgnoreRhosts yes
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000107-VMM-000530'
  tag gid: 'V-239268'
  tag rid: 'SV-239268r674733_rule'
  tag stig_id: 'ESXI-67-000012'
  tag fix_id: 'F-42460r674732_fix'
  tag cci: ['CCI-000767']
  tag nist: ['IA-2 (3)']

  command = "$vmhost = Get-VMHost -Name #{input('vmhostName')}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq '#{input('dodStigVibRootEnabled')}' -or $_.Name -eq '#{input('dodStigVibRootDisabled')}'}"
  describe powercli_command(command) do
    its('stdout.strip') { should_not cmp '' }
  end
end
