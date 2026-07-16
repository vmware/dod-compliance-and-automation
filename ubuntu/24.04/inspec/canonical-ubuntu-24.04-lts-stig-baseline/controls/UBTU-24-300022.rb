control 'UBTU-24-300022' do
  title 'Ubuntu 24.04 LTS must be configured so that remote X connections are disabled, unless to fulfill documented and validated mission requirements.'
  desc "The security risk of using X11 forwarding is that the client's X11 display server may be exposed to attack when the SSH client requests forwarding. A system administrator (SA) must protect clients that may expose themselves to attack by unwittingly requesting X11 forwarding, which can warrant a ''no'' setting.

X11 forwarding must be enabled with caution. Users with the ability to bypass file permissions on the remote host (for the user's X11 authorization database) can access the local X11 display through the forwarded connection. An attacker may then be able to perform activities such as keystroke monitoring if the ForwardX11Trusted option is also enabled.

If X11 services are not required for the system's intended function, they must be disabled or restricted as appropriate to the system's needs."
  desc 'check', 'Verify that X11Forwarding is disabled with the following command:

$ sudo grep -ir x11forwarding /etc/ssh/sshd_config* | grep -v "^#"
X11Forwarding no

If the "X11Forwarding" keyword is set to "yes" and is not documented with the information system security officer (ISSO) as an operational requirement, is missing, or multiple conflicting results are returned, this is a finding.'
  desc 'fix', 'Edit the "/etc/ssh/sshd_config" file to uncomment or add the line for the "X11Forwarding" keyword and set its value to "no" (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor):

X11Forwarding no

Restart the SSH daemon for the changes to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.7
  tag check_id: 'C-74741r1066611_chk'
  tag severity: 'high'
  tag gid: 'V-270708'
  tag rid: 'SV-270708r1066613_rule'
  tag stig_id: 'UBTU-24-300022'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-74642r1066612_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  sshdcommand = input('sshdcommand')

  describe command("#{sshdcommand}|&grep -i X11Forwarding") do
    its('stdout.strip') { should cmp 'X11Forwarding no' }
  end
end
