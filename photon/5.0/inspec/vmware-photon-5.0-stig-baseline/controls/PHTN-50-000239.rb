control 'PHTN-50-000239' do
  title 'The Photon operating system must implement only approved Message Authentication Codes (MACs) to protect the integrity of remote access sessions.'
  desc  "
    Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

    Remote access (e.g., RDP) is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

    Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify the running configuration of sshd:

    # sshd -T|&grep -i MACs

    Example result:

    macs hmac-sha2-512,hmac-sha2-256

    If the output matches the macs in the example result or a subset thereof, this is not a finding.

    If the output contains any macs not listed in the example result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/ssh/sshd_config

    Ensure the \"MACs\" line is uncommented and set to the following:

    MACs hmac-sha2-512,hmac-sha2-256

    At the command line, run the following command:

    # systemctl restart sshd.service
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag gid: 'V-PHTN-50-000239'
  tag rid: 'SV-PHTN-50-000239'
  tag stig_id: 'PHTN-50-000239'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']

  sshdMacs = input('sshdMacs')
  sshdcommand = input('sshdcommand')
  macs = command("#{sshdcommand}|&grep -i MACs").stdout.strip.delete_prefix('macs ').split(',')

  if !macs.empty?
    macs.each do |mac|
      describe mac do
        it { should be_in sshdMacs }
      end
    end
  else
    describe 'No SSH MACs found...skipping...' do
      skip 'No SSH MACs found...skipping...'
    end
  end
end
