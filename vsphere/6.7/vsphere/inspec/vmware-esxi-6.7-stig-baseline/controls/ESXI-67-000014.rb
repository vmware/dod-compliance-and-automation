control 'ESXI-67-000014' do
  title 'The ESXi host SSH daemon must not permit root logins.'
  desc  "Permitting direct root login reduces auditable information about who
ran privileged commands on the system and also allows direct attack attempts on
root's password."
  desc  'rationale', ''
  desc  'check', "
    From an SSH session connected to the ESXi host, or from the ESXi shell, run
the following command:

    # grep -i \"^PermitRootLogin\" /etc/ssh/sshd_config

    If there is no output or the output is not exactly \"PermitRootLogin no\",
this is a finding.
  "
  desc 'fix', "
    From an SSH session connected to the ESXi host, or from the ESXi shell, add
or correct the following line in \"/etc/ssh/sshd_config\":

    Add or correct the following line in \"/etc/ssh/sshd_config\":

    PermitRootLogin no
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-239270'
  tag rid: 'SV-239270r674739_rule'
  tag stig_id: 'ESXI-67-000014'
  tag fix_id: 'F-42462r674738_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  command = "$vmhost = Get-VMHost -Name #{input('vmhostName')}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq '#{input('dodStigVibRootEnabled')}' -or $_.Name -eq '#{input('dodStigVibRootDisabled')}'}"
  describe powercli_command(command) do
    its('stdout.strip') { should_not cmp '' }
  end
end
