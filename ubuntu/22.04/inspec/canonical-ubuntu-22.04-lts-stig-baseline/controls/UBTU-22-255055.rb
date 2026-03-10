control 'UBTU-22-255055' do
  title 'Ubuntu 22.04 LTS must configure the SSH daemon to use Message Authentication Codes (MACs) employing FIPS 140-3-approved cryptographic hashes to prevent the unauthorized disclosure of information and/or detect changes to information during transmission.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access (e.g., RDP) is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless. Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the internet) or an internal network.

Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection.

Encrypting information for transmission protects information from unauthorized disclosure and modification. Cryptographic mechanisms implemented to protect information integrity include, for example, cryptographic hash functions, which have common application in digital signatures, checksums, and message authentication codes.

'
  desc 'check', %q(Verify the SSH server is configured to only use MACs that employ FIPS 140-3 approved ciphers by using the following command:

     $ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'macs'
     /etc/ssh/sshd_config:MACs hmac-sha2-512,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-256-etm@openssh.com

If "MACs" does not contain only the hashes "hmac-sha2-512,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-256-etm@openssh.com" in exact order, is commented out, is missing, or conflicting results are returned, this is a finding.)
  desc 'fix', 'Configure the SSH server to only use MACs that employ FIPS 140-3 approved hashes.

Add or modify the following line in the "/etc/ssh/sshd_config" file:

MACs hmac-sha2-512,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-256-etm@openssh.com

Restart the SSH server for the changes to take effect:

     $ sudo systemctl reload sshd.service'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64261r953407_chk'
  tag severity: 'medium'
  tag gid: 'V-260532'
  tag rid: 'SV-260532r991554_rule'
  tag stig_id: 'UBTU-22-255055'
  tag gtitle: 'SRG-OS-000250-GPOS-00093'
  tag fix_id: 'F-64169r953408_fix'
  tag satisfies: ['SRG-OS-000250-GPOS-00093', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000424-GPOS-00188']
  tag 'documentable'
  tag cci: ['CCI-001453', 'CCI-002421', 'CCI-002890']
  tag nist: ['AC-17 (2)', 'SC-8 (1)', 'MA-4 (6)']

  sshdcommand = input('sshdcommand')

  describe command("#{sshdcommand}|&grep -i Macs").stdout.strip.delete_prefix('macs ') do
    it { should cmp 'hmac-sha2-512,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-256-etm@openssh.com' }
  end
end
