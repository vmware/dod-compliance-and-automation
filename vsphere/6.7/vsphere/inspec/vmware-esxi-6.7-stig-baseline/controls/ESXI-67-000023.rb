control 'ESXI-67-000023' do
  title "The ESXi host SSH daemon must be configured to not allow X11
forwarding."
  desc  "X11 forwarding over SSH allows for the secure remote execution of
X11-based applications. This feature can increase the attack surface of an SSH
connection."
  desc  'rationale', ''
  desc  'check', "
    From an SSH session connected to the ESXi host, or from the ESXi shell, run
the following command:

    # grep -i \"^X11Forwarding\" /etc/ssh/sshd_config

    If there is no output or the output is not exactly \"X11Forwarding no\",
this is a finding.
  "
  desc 'fix', "
    From an SSH session connected to the ESXi host, or from the ESXi shell, add
or correct the following line in \"/etc/ssh/sshd_config\":

    X11Forwarding no
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-239278'
  tag rid: 'SV-239278r674763_rule'
  tag stig_id: 'ESXI-67-000023'
  tag fix_id: 'F-42470r674762_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  command = "$vmhost = Get-VMHost -Name #{input('vmhostName')}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq '#{input('dodStigVibRootEnabled')}' -or $_.Name -eq '#{input('dodStigVibRootDisabled')}'}"
  describe powercli_command(command) do
    its('stdout.strip') { should_not cmp '' }
  end
end
