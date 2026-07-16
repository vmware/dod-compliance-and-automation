control 'UBTU-24-400400' do
  title 'Ubuntu 24.04 LTS must encrypt all stored passwords with a FIPS 140-3 approved cryptographic hashing algorithm.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.'
  desc 'check', 'Verify the shadow password suite configuration is set to encrypt passwords with a FIPS 140-3 approved cryptographic hashing algorithm with the following command:

$ grep -i ENCRYPT_METHOD /etc/login.defs
ENCRYPT_METHOD SHA512

If "ENCRYPT_METHOD" does not equal SHA512 or greater, this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to encrypt all stored passwords.

Edit/modify the following line in the "/etc/login.defs" file and set "ENCRYPT_METHOD" to SHA512:

ENCRYPT_METHOD SHA512'
  impact 0.5
  tag check_id: 'C-74772r1067123_chk'
  tag severity: 'medium'
  tag gid: 'V-270739'
  tag rid: 'SV-270739r1067124_rule'
  tag stig_id: 'UBTU-24-400400'
  tag gtitle: 'SRG-OS-000120-GPOS-00061'
  tag fix_id: 'F-74673r1066705_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']

  describe.one do
    describe login_defs do
      its('ENCRYPT_METHOD') { should cmp 'SHA512' }
    end
    describe login_defs do
      its('ENCRYPT_METHOD') { should cmp 'YESCRYPT' }
    end
  end
end
