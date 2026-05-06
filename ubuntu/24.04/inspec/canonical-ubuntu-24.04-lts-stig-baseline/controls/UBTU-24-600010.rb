control 'UBTU-24-600010' do
  title 'Ubuntu 24.04 LTS must immediately terminate all network connections associated with SSH traffic at the end of the session or after 10 minutes of inactivity.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element.

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at Ubuntu 24.04 LTS level, and de-allocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection. This does not mean that Ubuntu 24.04 LTS terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.'
  desc 'check', 'Verify that all network connections associated with SSH traffic are automatically terminated at the end of the session or after 10 minutes of inactivity with the following command:

$ grep -ir ClientAliveInterval /etc/ssh/sshd_config*
/etc/ssh/sshd_config:ClientAliveInterval 600

If "ClientAliveInterval" does not exist, is not set to a value of "600" or less in "/etc/ssh/sshd_config", if conflicting results are returned, is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to automatically terminate all network connections associated with SSH traffic at the end of a session or after a 10-minute period of inactivity.

In the file /etc/ssh/sshd_config set ClientAliveInterval to a value of "600" or less:

ClientAliveInterval 600

Restart the SSH daemon for the changes to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.5
  tag check_id: 'C-74776r1066716_chk'
  tag severity: 'medium'
  tag gid: 'V-270743'
  tag rid: 'SV-270743r1066718_rule'
  tag stig_id: 'UBTU-24-600010'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-74677r1066717_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']

  sshdcommand = input('sshdcommand')

  describe command("#{sshdcommand}|&grep -i ClientAliveInterval") do
    its('stdout.strip') { should cmp 'ClientAliveInterval 600' }
  end
end
