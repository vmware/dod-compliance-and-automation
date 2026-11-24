control 'UBTU-24-500050' do
  title 'Ubuntu 24.04 LTS must use strong authenticators in establishing nonlocal maintenance and diagnostic sessions.'
  desc 'Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the internet) or an internal network. Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection. Typically, strong authentication requires authenticators that are resistant to replay attacks and employ multifactor authentication. Strong authenticators include, for example, PKI where certificates are stored on a token protected by a password, passphrase, or biometric.'
  desc 'check', 'Verify Ubuntu 24.04 LTS is configured to use strong authenticators in the establishment of nonlocal maintenance and diagnostic maintenance with the following command:

$ sudo grep -r ^UsePAM /etc/ssh/sshd_config*
/etc/ssh/sshd_config:UsePAM yes

If "UsePAM" is not set to "yes", conflicting results are returned, the line is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to use strong authentication when establishing nonlocal maintenance and diagnostic sessions.

Add or modify the following line to /etc/ssh/sshd_config:

UsePAM yes'
  impact 0.5
  tag check_id: 'C-74774r1066710_chk'
  tag severity: 'medium'
  tag gid: 'V-270741'
  tag rid: 'SV-270741r1066712_rule'
  tag stig_id: 'UBTU-24-500050'
  tag gtitle: 'SRG-OS-000125-GPOS-00065'
  tag fix_id: 'F-74675r1066711_fix'
  tag 'documentable'
  tag cci: ['CCI-000877']
  tag nist: ['MA-4 c']

  sshdcommand = input('sshdcommand')

  describe command("#{sshdcommand}|&grep -i UsePAM") do
    its('stdout.strip') { should cmp 'UsePAM yes' }
  end
end
