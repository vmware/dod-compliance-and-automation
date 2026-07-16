control 'UBTU-24-100840' do
  title 'Ubuntu 24.04 LTS SSH server must be configured to use only FIPS 140-3 validated key exchange algorithms.'
  desc 'Without cryptographic integrity protections provided by FIPS-validated cryptographic algorithms, information can be viewed and altered by unauthorized users without detection.

The system will attempt to use the first algorithm presented by the client that matches the server list.'
  desc 'check', 'Verify that the SSH daemon is configured to use only FIPS-validated key exchange algorithms with the following command:

$ sudo grep -ir kexalgorithms /etc/ssh/sshd_config*
KexAlgorithms ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256

If "KexAlgorithms" does not contain only the algorithms "ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256", is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure the SSH daemon to use only FIPS-validated key exchange algorithms by adding or modifying the following line in "/etc/ssh/sshd_config":

KexAlgorithms ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256

Restart the "sshd" service for changes to take effect:

$ sudo systemctl restart sshd'
  impact 0.5
  tag check_id: 'C-74702r1134803_chk'
  tag severity: 'medium'
  tag gid: 'V-270669'
  tag rid: 'SV-270669r1134804_rule'
  tag stig_id: 'UBTU-24-100840'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-74603r1066495_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']

  sshdcommand = input('sshdcommand')

  describe command("#{sshdcommand}|&grep -i ^KexAlgorithms").stdout.strip.delete_prefix('kexalgorithms ') do
    it { should cmp 'ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256' }
  end
end
