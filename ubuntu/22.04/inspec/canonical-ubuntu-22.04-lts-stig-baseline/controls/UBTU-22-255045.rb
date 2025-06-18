control 'UBTU-22-255045' do
  title 'Ubuntu 22.04 LTS SSH daemon must prevent remote hosts from connecting to the proxy display.'
  desc 'When X11 forwarding is enabled, there may be additional exposure to the server and client displays if the sshd proxy display is configured to listen on the wildcard address. By default, sshd binds the forwarding server to the loopback address and sets the hostname part of the DISPLAY environment variable to localhost. This prevents remote hosts from connecting to the proxy display.'
  desc 'check', %q(Verify the SSH server prevents remote hosts from connecting to the proxy display by using the following command:

     $ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'x11uselocalhost'
     /etc/ssh/sshd_config:X11UseLocalhost yes

If "X11UseLocalhost" is set to "no", is commented out, is missing, or conflicting results are returned, this is a finding.)
  desc 'fix', 'Configure the SSH server to prevent remote hosts from connecting to the proxy display.

Add or modify the following line in the "/etc/ssh/sshd_config" file:

X11UseLocalhost yes

Restart the SSH daemon for the changes to take effect:

     $ sudo systemctl restart sshd.service'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64259r953401_chk'
  tag severity: 'medium'
  tag gid: 'V-260530'
  tag rid: 'SV-260530r991589_rule'
  tag stig_id: 'UBTU-22-255045'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-64167r953402_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  sshdcommand = input('sshdcommand')

  describe command("#{sshdcommand}|&grep -i X11UseLocalhost") do
    its('stdout.strip') { should cmp 'X11UseLocalhost yes' }
  end
end
