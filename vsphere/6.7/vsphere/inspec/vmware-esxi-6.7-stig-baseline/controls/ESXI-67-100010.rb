control 'ESXI-67-100010' do
  title "The ESXi host SSH daemon must be configured to only use FIPS 140-2
approved ciphers."
  desc  "Approved algorithms should impart some level of confidence in their
implementation. These are also required for compliance."
  desc  'rationale', ''
  desc  'check', "
    Verify that only FIPS-approved ciphers are used by running the following
command:

    # grep -i \"^Ciphers\" /etc/ssh/sshd_config

    If there is no output, or the output is not exactly \"Ciphers
aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\",
this is a finding.
  "
  desc 'fix', "
    Limit the ciphers to algorithms that are FIPS approved. Counter (CTR) mode
is also preferred over cipher-block chaining (CBC) mode.

    Add or correct the following line in \"/etc/ssh/sshd_config\":

    Ciphers
aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000478-VMM-001980'
  tag gid: 'V-239331'
  tag rid: 'SV-239331r816580_rule'
  tag stig_id: 'ESXI-67-100010'
  tag fix_id: 'F-42523r816579_fix'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13']

  command = "$vmhost = Get-VMHost -Name #{input('vmhostName')}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.software.vib.list.Invoke() | Where {$_.Name -eq '#{input('dodStigVibRootEnabled')}' -or $_.Name -eq '#{input('dodStigVibRootDisabled')}'}"
  describe powercli_command(command) do
    its('stdout.strip') { should_not cmp '' }
  end
end
