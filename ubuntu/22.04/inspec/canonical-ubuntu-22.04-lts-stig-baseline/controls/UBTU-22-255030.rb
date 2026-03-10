control 'UBTU-22-255030' do
  title 'Ubuntu 22.04 LTS must be configured so that all network connections associated with SSH traffic terminate after becoming unresponsive.'
  desc 'Terminating an unresponsive SSH session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle SSH session will also free up resources committed by the managed network element.

Terminating network connections associated with communications sessions includes, for example, deallocating associated TCP/IP address/port pairs at the operating system level and deallocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection. This does not mean the operating system terminates all sessions or network access; it only ends the unresponsive session and releases the resources associated with that session.'
  desc 'check', %q(Verify the SSH server automatically terminates a user session after the SSH client has become unresponsive by using the following command:

     $ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'clientalivecountmax'
     /etc/ssh/sshd_config:ClientAliveCountMax 1

If "ClientAliveCountMax" is not to "1", if conflicting results are returned, is commented out, or is missing, this is a finding.)
  desc 'fix', 'Configure the SSH server to terminate a user session automatically after the SSH client has become unresponsive.

Note: This setting must be applied in conjunction with UBTU-22-255040 to function correctly.

Add or modify the following line in the "/etc/ssh/sshd_config" file:

ClientAliveCountMax 1

Restart the SSH daemon for the changes to take effect:

     $ sudo systemctl restart sshd.service'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64256r953392_chk'
  tag severity: 'medium'
  tag gid: 'V-260527'
  tag rid: 'SV-260527r986275_rule'
  tag stig_id: 'UBTU-22-255030'
  tag gtitle: 'SRG-OS-000126-GPOS-00066'
  tag fix_id: 'F-64164r953393_fix'
  tag 'documentable'
  tag cci: ['CCI-000879', 'CCI-001133']
  tag nist: ['MA-4 e', 'SC-10']

  sshdcommand = input('sshdcommand')

  describe command("#{sshdcommand}|&grep -i ClientAliveCountMax") do
    its('stdout.strip') { should cmp 'ClientAliveCountMax 1' }
  end
end
