control 'UBTU-24-100860' do
  title 'Ubuntu 24.04 LTS SSH client must be configured to use only Message Authentication Codes (MACs) employing FIPS 140-3 validated cryptographic hash algorithms.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access (e.g., RDP) is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless. Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the internet) or an internal network.

Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection.

Encrypting information for transmission protects information from unauthorized disclosure and modification. Cryptographic mechanisms implemented to protect information integrity include, for example, cryptographic hash functions that have common application in digital signatures, checksums, and message authentication codes.'
  desc 'check', 'Verify the SSH client is configured to only use MACs employing FIPS 140-3 approved algorithms with the following command:

$ sudo grep -ir macs /etc/ssh/ssh_config*
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256

If any MACs other than "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256" are listed, or the returned line is commented out, this is a finding.'
  desc 'fix', 'Configure the Ubuntu 24.04 LTS SSH client to use only MACs employing FIPS 140-3 approved algorithms by updating the "/etc/ssh/ssh_config" file with the following line:

MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256

Restart the "ssh" service for changes to take effect:

$ sudo systemctl restart ssh'
  impact 0.5
  tag check_id: 'C-74704r1155228_chk'
  tag severity: 'medium'
  tag gid: 'V-270671'
  tag rid: 'SV-270671r1155244_rule'
  tag stig_id: 'UBTU-24-100860'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag fix_id: 'F-74605r1067117_fix'
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']

  describe ssh_config do
    its('MACs') { should cmp 'hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256' }
  end
end
