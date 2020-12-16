# encoding: UTF-8

control 'V-219151' do
  title "The Ubuntu operating system must implement NIST FIPS-validated
cryptography to protect classified information and for the following: to
provision digital signatures, to generate cryptographic hashes, and to protect
unclassified information requiring confidentiality and cryptographic protection
in accordance with applicable federal laws, Executive Orders, directives,
policies, regulations, and standards."
  desc  "Use of weak or untested encryption algorithms undermines the purposes
of utilizing encryption to protect data. The operating system must implement
cryptographic modules adhering to the higher standards approved by the federal
government since this provides assurance they have been tested and validated.


  "
  desc  'rationale', ''
  desc  'check', "
    Verify the system is configured to run in FIPS mode.

    Check that the system is configured to run in FIPS mode with the following
command:

    # grep -i 1 /proc/sys/crypto/fips_enabled
    1

    If a value of \"1\" is not returned, this is a finding.
  "
  desc  'fix', "
    Configure the system to run in FIPS mode. Add \"fips=1\" to the kernel
parameter during the Ubuntu operating systems install.

    Enabling a FIPS mode on a pre-existing system involves a number of
modifications to the Ubuntu operating system. Refer to the Ubuntu Server 18.04
FIPS 140-2 security policy document for instructions. A subscription to the
\"Ubuntu Advantage\" plan is required in order to obtain the FIPS Kernel
cryptographic modules and enable FIPS.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000478-GPOS-00223'
  tag satisfies: ['SRG-OS-000478-GPOS-00223', 'SRG-OS-000396-GPOS-00176']
  tag gid: 'V-219151'
  tag rid: 'SV-219151r508662_rule'
  tag stig_id: 'UBTU-18-010005'
  tag fix_id: 'F-20875r304782_fix'
  tag cci: ['V-100527', 'SV-109631', 'CCI-002450']
  tag nist: ['SC-13']
  config_file = '/proc/sys/crypto/fips_enabled'
  config_file_exists = file(config_file).exist?

  if config_file_exists
    describe file(config_file) do
      its('content') { should match %r{\A1\Z} }
    end
  else
    describe ('FIPS is enabled') do
      subject { config_file_exists }
      it { should be true }
    end
  end
end

