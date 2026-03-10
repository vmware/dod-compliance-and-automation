control 'UBTU-22-255060' do
  title 'Ubuntu 22.04 LTS SSH server must be configured to use only FIPS-validated key exchange algorithms.'
  desc 'Without cryptographic integrity protections provided by FIPS-validated cryptographic algorithms, information can be viewed and altered by unauthorized users without detection.

The system will attempt to use the first algorithm presented by the client that matches the server list. Listing the values "strongest to weakest" is a method to ensure the use of the strongest algorithm available to secure the SSH connection.'
  desc 'check', %q(Verify that the SSH server is configured to use only FIPS-validated key exchange algorithms by using the following command:

     $ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'kexalgorithms'
     /etc/ssh/sshd_config:KexAlgorithms ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256

If "KexAlgorithms" does not contain only the algorithms "ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256" in exact order, is commented out, is missing, or conflicting results are returned, this is a finding.)
  desc 'fix', 'Configure the SSH server to use only FIPS-validated key exchange algorithms.

Add or modify the following line in the "/etc/ssh/sshd_config" file:

KexAlgorithms ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256

Restart the SSH server for changes to take effect:

     $ sudo systemctl restart sshd.service'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64262r953410_chk'
  tag severity: 'medium'
  tag gid: 'V-260533'
  tag rid: 'SV-260533r958408_rule'
  tag stig_id: 'UBTU-22-255060'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-64170r953411_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']

  sshdcommand = input('sshdcommand')

  describe command("#{sshdcommand}|&grep -i ^KexAlgorithms").stdout.strip.delete_prefix('kexalgorithms ') do
    it { should cmp 'ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256' }
  end
end
