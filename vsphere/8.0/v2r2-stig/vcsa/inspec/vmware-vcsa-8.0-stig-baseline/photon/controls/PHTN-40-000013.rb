control 'PHTN-40-000013' do
  title 'The Photon operating system must have the OpenSSL FIPS provider installed to protect the confidentiality of remote access sessions.'
  desc 'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.

OpenSSH on the Photon operating system when configured appropriately can utilize a FIPS validated OpenSSL for cryptographic operations.
'
  desc 'check', 'At the command line, run the following command to verify the OpenSSL FIPS provider is installed:

# rpm -qa | grep openssl-fips

Example result:

openssl-fips-provider-3.0.3-1.ph4.x86_64

If there is no output indicating that the OpenSSL FIPS provider is installed, this is a finding.'
  desc 'fix', 'At the command line, run the following command:

# tdnf install openssl-fips-provider'
  impact 0.7
  tag check_id: 'C-62546r933477_chk'
  tag severity: 'high'
  tag gid: 'V-258806'
  tag rid: 'SV-258806r958408_rule'
  tag stig_id: 'PHTN-40-000013'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-62455r933478_fix'
  tag satisfies: ['SRG-OS-000033-GPOS-00014', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174', 'SRG-OS-000423-GPOS-00187', 'SRG-OS-000425-GPOS-00189', 'SRG-OS-000426-GPOS-00190']
  tag cci: ['CCI-000068', 'CCI-002418', 'CCI-002420', 'CCI-002422', 'CCI-002890', 'CCI-003123']
  tag nist: ['AC-17 (2)', 'SC-8', 'SC-8 (2)', 'SC-8 (2)', 'MA-4 (6)', 'MA-4 (6)']

  describe command('rpm -qa | grep openssl-fips') do
    its('stdout.strip') { should match /openssl-fips-provider/ }
  end
  # Test whether OpenSSL is operating in FIPS mode system wide
  describe command('openssl md5 /etc/ssh/sshd_config') do
    its('stdout.strip') { should cmp '' }
    its('stderr.strip') { should match /unsupported:crypto/ }
  end
end
