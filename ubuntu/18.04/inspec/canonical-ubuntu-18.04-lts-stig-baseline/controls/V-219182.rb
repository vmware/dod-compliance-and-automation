# encoding: UTF-8

control 'V-219182' do
  title "The Ubuntu operating system must employ a FIPS 140-2 approved
cryptographic hashing algorithms for all created and stored passwords."
  desc  "The Ubuntu operating system must use a FIPS-compliant hashing
algorithm to securely store the password. The FIPS-compliant hashing algorithm
parameters must be selected in order to harden the system against offline
attacks."
  desc  'rationale', ''
  desc  'check', "
    Verify that encrypted passwords stored in /etc/shadow use a strong
cryptographic hash.

    Check that pam_unix.so auth is configured to use sha512 with the following
command:

    # grep password /etc/pam.d/common-password | grep pam_unix

    password [success=1 default=ignore] pam_unix.so obscure sha512

    If \"sha512\" is not an option of the output, or is commented out, this is
a finding.

    Check that ENCRYPT_METHOD is set to sha512 in /etc/login.defs:

    # grep -i ENCRYPT_METHOD /etc/login.defs

    ENCRYPT_METHOD SHA512

    If the output does not contain \"sha512\", or it is commented out, this is
a finding.
  "
  desc  'fix', "
    Configure the Ubuntu operating system to encrypt all stored passwords with
a strong cryptographic hash.

    Edit/modify the following line in the file \"/etc/pam.d/common-password\"
file to include the sha512 option for pam_unix.so:

    password [success=1 default=ignore] pam_unix.so obscure sha512

    Edit/modify /etc/login.defs and set \"ENCRYPT_METHOD sha512\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000120-GPOS-00061'
  tag gid: 'V-219182'
  tag rid: 'SV-219182r508662_rule'
  tag stig_id: 'UBTU-18-010110'
  tag fix_id: 'F-20906r304875_fix'
  tag cci: ['SV-109695', 'V-100591', 'CCI-000803']
  tag nist: ['IA-7']

  describe login_defs do
    its('ENCRYPT_METHOD') { should eq 'SHA512' }
  end
end

