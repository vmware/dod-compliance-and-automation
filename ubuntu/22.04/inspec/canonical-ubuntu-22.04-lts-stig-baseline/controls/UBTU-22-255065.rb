control 'UBTU-22-255065' do
  title 'Ubuntu 22.04 LTS must use strong authenticators in establishing nonlocal maintenance and diagnostic sessions.'
  desc 'Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the internet) or an internal network. Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection. Typically, strong authentication requires authenticators that are resistant to replay attacks and employ multifactor authentication. Strong authenticators include, for example, PKI where certificates are stored on a token protected by a password, passphrase, or biometric.'
  desc 'check', %q(Verify Ubuntu 22.04 LTS is configured to use strong authenticators in the establishment of nonlocal maintenance and diagnostic maintenance by using the following command:

     $ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'usepam'
     /etc/ssh/sshd_config:UsePAM yes

If "UsePAM" is not set to "yes", is commented out, is missing, or conflicting results are returned, this is a finding.)
  desc 'fix', 'Configure Ubuntu 22.04 LTS to use strong authentication when establishing nonlocal maintenance and diagnostic sessions.

Add or modify the following line to /etc/ssh/sshd_config:

UsePAM yes

Restart the SSH server for changes to take effect:

     $ sudo systemctl restart sshd.service'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64263r953413_chk'
  tag severity: 'medium'
  tag gid: 'V-260534'
  tag rid: 'SV-260534r958510_rule'
  tag stig_id: 'UBTU-22-255065'
  tag gtitle: 'SRG-OS-000125-GPOS-00065'
  tag fix_id: 'F-64171r953414_fix'
  tag 'documentable'
  tag cci: ['CCI-000877']
  tag nist: ['MA-4 c']

  sshdcommand = input('sshdcommand')

  describe command("#{sshdcommand}|&grep -i UsePAM") do
    its('stdout.strip') { should cmp 'UsePAM yes' }
  end
end
