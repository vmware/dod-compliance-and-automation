control 'ESXI-67-000016' do
  title 'The ESXi host SSH daemon must not permit user environment settings.'
  desc  "SSH environment options potentially allow users to bypass access
restriction in some configurations. Users must not be able to present
environment options to the SSH daemon."
  desc  'rationale', ''
  desc  'check', "
    From an SSH session connected to the ESXi host, or from the ESXi shell, run
the following command:

    # grep -i \"^PermitUserEnvironment\" /etc/ssh/sshd_config

    If there is no output or the output is not exactly \"PermitUserEnvironment
no\", this is a finding.
  "
  desc 'fix', "
    From an SSH session connected to the ESXi host, or from the ESXi shell, add
or correct the following line in \"/etc/ssh/sshd_config\":

    PermitUserEnvironment no
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-239272'
  tag rid: 'SV-239272r674745_rule'
  tag stig_id: 'ESXI-67-000016'
  tag fix_id: 'F-42464r674744_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  command = "$vmhost = Get-VMHost -Name #{input('vmhostName')}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq '#{input('dodStigVibRootEnabled')}' -or $_.Name -eq '#{input('dodStigVibRootDisabled')}'}"
  describe powercli_command(command) do
    its('stdout.strip') { should_not cmp '' }
  end
end
