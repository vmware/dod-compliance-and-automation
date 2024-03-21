control 'PHTN-50-000079' do
  title 'The Photon operating system must implement only approved ciphers to protect the integrity of remote access sessions.'
  desc  "
    Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

    Remote access (e.g., RDP) is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

    Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify the running configuration of sshd:

    # sshd -T|&grep -i Ciphers

    Expected result:

    ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

    If the output matches the ciphers in the expected result or a subset thereof, this is not a finding.

    If the ciphers in the output contain any ciphers not listed in the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/ssh/sshd_config

    Ensure the \"Ciphers\" line is uncommented and set to the following:

    Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

    At the command line, run the following command:

    # systemctl restart sshd.service
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag gid: 'V-PHTN-50-000079'
  tag rid: 'SV-PHTN-50-000079'
  tag stig_id: 'PHTN-50-000079'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']

  sshdCiphers = input('sshdCiphers')
  sshdcommand = input('sshdcommand')
  ciphers = command("#{sshdcommand}|&grep -i Ciphers").stdout.strip.delete_prefix('ciphers ').split(',')

  if !ciphers.empty?
    ciphers.each do |cipher|
      describe cipher do
        it { should be_in sshdCiphers }
      end
    end
  else
    describe 'No SSH ciphers found...skipping...' do
      skip 'No SSH ciphers found...skipping...'
    end
  end
end
