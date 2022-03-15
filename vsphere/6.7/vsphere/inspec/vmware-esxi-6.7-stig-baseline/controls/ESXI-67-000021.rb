control 'ESXI-67-000021' do
  title "The ESXi host SSH daemon must not allow compression or must only allow
compression after successful authentication."
  desc  "If compression is allowed in an SSH connection prior to
authentication, vulnerabilities in the compression software could result in
compromise of the system from an unauthenticated connection, potentially with
root privileges."
  desc  'rationale', ''
  desc  'check', "
    From an SSH session connected to the ESXi host, or from the ESXi shell, run
the following command:

    # grep -i \"^Compression\" /etc/ssh/sshd_config

    If there is no output or the output is not exactly \"Compression no\", this
is a finding.
  "
  desc 'fix', "
    From an SSH session connected to the ESXi host, or from the ESXi shell, add
or correct the following line in \"/etc/ssh/sshd_config\":

    Compression no
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-239276'
  tag rid: 'SV-239276r674757_rule'
  tag stig_id: 'ESXI-67-000021'
  tag fix_id: 'F-42468r674756_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  command = "$vmhost = Get-VMHost -Name #{input('vmhostName')}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq '#{input('dodStigVibRootEnabled')}' -or $_.Name -eq '#{input('dodStigVibRootDisabled')}'}"
  describe powercli_command(command) do
    its('stdout.strip') { should_not cmp '' }
  end
end
