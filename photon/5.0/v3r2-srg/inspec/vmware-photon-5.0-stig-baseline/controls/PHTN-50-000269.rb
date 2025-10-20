control 'PHTN-50-000269' do
  title 'The Photon operating system SSH server must be configured to use only FIPS 140-3 validated key exchange algorithms.'
  desc  "
    Without cryptographic integrity protections provided by FIPS-validated cryptographic algorithms, information can be viewed and altered by unauthorized users without detection.

    The system will attempt to use the first algorithm presented by the client that matches the server list.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify the running configuration of sshd:

    # sshd -T|&grep -i KexAlgorithms

    Expected result:

    kexalgorithms ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256

    If the output matches the kexalgorithms in the expected result or a subset thereof, this is not a finding.

    If the kexalgorithms in the output contain any kexalgorithms not listed in the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/ssh/sshd_config

    Ensure the \"KexAlgorithms\" line is uncommented and set to the following:

    KexAlgorithms ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256

    At the command line, run the following command:

    # systemctl restart sshd.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-PHTN-50-000269'
  tag rid: 'SV-PHTN-50-000269'
  tag stig_id: 'PHTN-50-000269'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  sshdKexAlgorithms = input('sshdKexAlgorithms')
  sshdcommand = input('sshdcommand')
  kexalgorithms = command("#{sshdcommand}|&grep -i KexAlgorithms").stdout.strip.delete_prefix('kexalgorithms ').split(',')

  if !kexalgorithms.empty?
    kexalgorithms.each do |kexalgorithm|
      describe kexalgorithm do
        it { should be_in sshdKexAlgorithms }
      end
    end
  else
    describe 'No SSH sshdKexAlgorithms found...skipping...' do
      skip 'No SSH sshdKexAlgorithms found...skipping...'
    end
  end
end
