control 'UBTU-24-100820' do
  title 'Ubuntu 24.04 LTS must configure the SSH daemon to use FIPS 140-3 approved ciphers to prevent the unauthorized disclosure of information and/or detect changes to information during transmission.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access (e.g., RDP) is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the internet) or an internal network.

Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection.

Encrypting information for transmission protects information from unauthorized disclosure and modification. Cryptographic mechanisms implemented to protect information integrity include, for example, cryptographic hash functions that have common application in digital signatures, checksums, and message authentication codes.

'
  desc 'check', %q(Verify that the SSH daemon is configured to implement only FIPS-approved algorithms with the following command:

$ sudo grep -r 'Ciphers' /etc/ssh/sshd_config*
Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes128-ctr

If any ciphers other than "Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes128-ctr" are listed, the "Ciphers" keyword is missing, or the returned line is commented out, or if multiple conflicting ciphers are returned, this is a finding.)
  desc 'fix', 'Configure Ubuntu 24.04 LTS to allow the SSH daemon to only implement FIPS-approved algorithms.

Add the following line (or modify the line to have the required value) to the "/etc/ssh/sshd_config" file (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor):

Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes128-ctr

Restart the "sshd" service for changes to take effect:

$ sudo systemctl restart sshd'
  impact 0.5
  tag check_id: 'C-74700r1067106_chk'
  tag severity: 'medium'
  tag gid: 'V-270667'
  tag rid: 'SV-270667r1067107_rule'
  tag stig_id: 'UBTU-24-100820'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-74601r1066489_fix'
  tag satisfies: ['SRG-OS-000033-GPOS-00014', 'SRG-OS-000394-GPOS-00174', 'SRG-OS-000424-GPOS-00188']
  tag 'documentable'
  tag cci: ['CCI-000068', 'CCI-003123', 'CCI-002421']
  tag nist: ['AC-17 (2)', 'MA-4 (6)', 'SC-8 (1)']

  sshdcommand = input('sshdcommand')

  describe command("#{sshdcommand}|&grep -i Ciphers").stdout.strip.delete_prefix('ciphers ') do
    it { should cmp 'aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes128-ctr' }
  end
end
