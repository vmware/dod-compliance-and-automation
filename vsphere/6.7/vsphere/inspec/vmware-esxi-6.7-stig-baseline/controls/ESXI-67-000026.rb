control 'ESXI-67-000026' do
  title 'The ESXi host SSH daemon must set a timeout count on idle sessions.'
  desc  "Setting a timeout ensures that a user login will be terminated as soon
as the \"ClientAliveCountMax\" is reached."
  desc  'rationale', ''
  desc  'check', "
    From an SSH session connected to the ESXi host, or from the ESXi shell, run
the following command:

    # grep -i \"^ClientAliveCountMax\" /etc/ssh/sshd_config

    If there is no output or the output is not exactly \"ClientAliveCountMax
3\", this is a finding.
  "
  desc 'fix', "
    From an SSH session connected to the ESXi host, or from the ESXi shell, add
or correct the following line in \"/etc/ssh/sshd_config\":

    ClientAliveCountMax 3
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-239281'
  tag rid: 'SV-239281r674772_rule'
  tag stig_id: 'ESXI-67-000026'
  tag fix_id: 'F-42473r674771_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  command = "$vmhost = Get-VMHost -Name #{input('vmhostName')}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq '#{input('dodStigVibRootEnabled')}' -or $_.Name -eq '#{input('dodStigVibRootDisabled')}'}"
  describe powercli_command(command) do
    its('stdout.strip') { should_not cmp '' }
  end
end
