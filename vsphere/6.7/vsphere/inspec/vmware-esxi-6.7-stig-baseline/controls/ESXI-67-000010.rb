control 'ESXI-67-000010' do
  title "The ESXi host SSH daemon must use DoD-approved encryption to protect
the confidentiality of remote access sessions."
  desc  "Approved algorithms should impart some level of confidence in their
implementation. Limit the ciphers to algorithms that are FIPS approved. Counter
(CTR) mode is also preferred over cipher-block chaining (CBC) mode."
  desc  'rationale', ''
  desc  'check', "
    To verify that only FIPS-approved ciphers are in use, run the following
command from an SSH session connected to the ESXi host, or from the ESXi shell:

    # grep -i \"^FipsMode\" /etc/ssh/sshd_config

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the
following commands:

    $esxcli = Get-EsxCli -v2
    $esxcli.system.security.fips140.ssh.get.invoke()

    If there is no output or the output is not exactly \"FipsMode yes\" over
SSH, or enabled is not \"true\" over PowerCLI, this is a finding.
  "
  desc 'fix', "
    Limit the ciphers to FIPS-approved algorithms.

    From an SSH session connected to the ESXi host, or from the ESXi shell, add
or correct the following line in \"/etc/ssh/sshd_config\":

    FipsMode yes

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the
following commands:

    $esxcli = Get-EsxCli -v2
    $arguments = $esxcli.system.security.fips140.ssh.set.CreateArgs()
    $arguments.enable = $true
    $esxcli.system.security.fips140.ssh.set.Invoke($arguments)
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000033-VMM-000140'
  tag gid: 'V-239267'
  tag rid: 'SV-239267r674730_rule'
  tag stig_id: 'ESXI-67-000010'
  tag fix_id: 'F-42459r674729_fix'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']

  command = "$vmhost = Get-VMHost -Name #{input('vmhostName')}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.system.security.fips140.ssh.get.invoke() | Select-Object -ExpandProperty Enabled"
  describe powercli_command(command) do
    its('stdout.strip') { should cmp 'true' }
  end
end
