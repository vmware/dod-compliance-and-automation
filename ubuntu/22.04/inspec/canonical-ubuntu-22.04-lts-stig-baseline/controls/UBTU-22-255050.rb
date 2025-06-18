control 'UBTU-22-255050' do
  title 'Ubuntu 22.04 LTS must configure the SSH daemon to use FIPS 140-3-approved ciphers to prevent the unauthorized disclosure of information and/or detect changes to information during transmission.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access (e.g., RDP) is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the internet) or an internal network.

Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection.

Encrypting information for transmission protects information from unauthorized disclosure and modification. Cryptographic mechanisms implemented to protect information integrity include, for example, cryptographic hash functions which have common application in digital signatures, checksums, and message authentication codes.

By specifying a cipher list with the order of ciphers being in a "strongest to weakest" orientation, the system will automatically attempt to use the strongest cipher for securing SSH connections.

'
  desc 'check', %q(Verify the SSH server is configured to only implement FIPS-approved ciphers with the following command:

     $ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'ciphers'
     /etc/ssh/sshd_config:Ciphers aes256-ctr,aes256-gcm@openssh.com,aes192-ctr,aes128-ctr,aes128-gcm@openssh.com

If "Ciphers" does not contain only the ciphers "aes256-ctr,aes256-gcm@openssh.com,aes192-ctr,aes128-ctr,aes128-gcm@openssh.com" in exact order, is commented out, is missing, or conflicting results are returned, this is a finding.)
  desc 'fix', 'Configure the SSH server to only implement FIPS-approved ciphers.

Add or modify the following line in the "/etc/ssh/sshd_config" file:

Ciphers aes256-ctr,aes256-gcm@openssh.com,aes192-ctr,aes128-ctr,aes128-gcm@openssh.com

Restart the SSH server for the changes to take effect:

     $ sudo systemctl restart sshd.service'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64260r953404_chk'
  tag severity: 'medium'
  tag gid: 'V-260531'
  tag rid: 'SV-260531r958408_rule'
  tag stig_id: 'UBTU-22-255050'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-64168r953405_fix'
  tag satisfies: ['SRG-OS-000033-GPOS-00014', 'SRG-OS-000394-GPOS-00174', 'SRG-OS-000424-GPOS-00188']
  tag 'documentable'
  tag cci: ['CCI-000068', 'CCI-002421', 'CCI-003123']
  tag nist: ['AC-17 (2)', 'SC-8 (1)', 'MA-4 (6)']

  sshdcommand = input('sshdcommand')

  describe command("#{sshdcommand}|&grep -i Ciphers").stdout.strip.delete_prefix('ciphers ') do
    it { should cmp 'aes256-ctr,aes256-gcm@openssh.com,aes192-ctr,aes128-ctr,aes128-gcm@openssh.com' }
  end
end
