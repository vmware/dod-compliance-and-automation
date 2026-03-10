control 'UBTU-22-611070' do
  title 'Ubuntu 22.04 LTS must encrypt all stored passwords with a FIPS 140-3-approved cryptographic hashing algorithm.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.'
  desc 'check', %q(Verify that the shadow password suite configuration is set to encrypt passwords with a FIPS 140-3 approved cryptographic hashing algorithm by using the following command:

     $ grep -i '^\s*encrypt_method' /etc/login.defs
     ENCRYPT_METHOD SHA512

If "ENCRYPT_METHOD" does not equal SHA512 or greater, is commented out, or is missing, this is a finding.)
  desc 'fix', 'Configure Ubuntu 22.04 LTS to encrypt all stored passwords.

Add or modify the following line in the "/etc/login.defs" file:

ENCRYPT_METHOD SHA512'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64301r953527_chk'
  tag severity: 'medium'
  tag gid: 'V-260572'
  tag rid: 'SV-260572r971535_rule'
  tag stig_id: 'UBTU-22-611070'
  tag gtitle: 'SRG-OS-000120-GPOS-00061'
  tag fix_id: 'F-64209r953528_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']

  describe login_defs do
    its('ENCRYPT_METHOD') { should eq 'SHA512' }
  end
end
