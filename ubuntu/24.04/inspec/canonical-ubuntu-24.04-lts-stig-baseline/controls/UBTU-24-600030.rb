control 'UBTU-24-600030' do
  title 'Ubuntu 24.04 LTS must implement NIST FIPS-validated cryptography to protect classified information and for the following: To provision digital signatures, to generate cryptographic hashes, and to protect unclassified information requiring confidentiality and cryptographic protection in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. Ubuntu 24.04 LTS must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

'
  desc 'check', 'Verify the system is configured to run in FIPS mode with the following command:

$ grep -i 1 /proc/sys/crypto/fips_enabled
1

If a value of "1" is not returned, this is a finding.'
  desc 'fix', 'Configure the system to run in FIPS mode. Add "fips=1" to the kernel parameter during Ubuntu 24.04 LTSs install.

Enabling a FIPS mode on a pre-existing system involves a number of modifications to Ubuntu 24.04 LTS. Refer to the Ubuntu Pro security certification documentation for instructions.

A subscription to the "Ubuntu Pro" plan is required to obtain the FIPS Kernel cryptographic modules and enable FIPS.

Note: Ubuntu Pro security certification instructions can be found at: https://ubuntu.com/security/certifications/docs/fips-enablement

The basic steps use the following commands:

$ sudo pro attach <token>
$ sudo pro enable fips-updates'
  impact 0.7
  tag check_id: 'C-74777r1066719_chk'
  tag severity: 'high'
  tag gid: 'V-270744'
  tag rid: 'SV-270744r1137699_rule'
  tag stig_id: 'UBTU-24-600030'
  tag gtitle: 'SRG-OS-000478-GPOS-00223'
  tag fix_id: 'F-74678r1066720_fix'
  tag satisfies: ['SRG-OS-000478-GPOS-00223', 'SRG-OS-000396-GPOS-00176']
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']

  fips_config_file = input('fips_config_file')
  fips_config_file_exists = file(fips_config_file).exist?

  if fips_config_file_exists
    describe file(fips_config_file) do
      its('content') { should cmp 1 }
    end
  else
    describe('FIPS is enabled') do
      subject { fips_config_file_exists }
      it { should be true }
    end
  end
end
