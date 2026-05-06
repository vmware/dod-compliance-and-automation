control 'UBTU-24-600000' do
  title 'Ubuntu 24.04 LTS must immediately terminate all network connections associated with SSH traffic after a period of inactivity.'
  desc "Automatic session termination addresses the termination of user-initiated logical sessions in contrast to the termination of network connections that are associated with communications sessions (i.e., network disconnect). A logical session (for local, network, and remote access) is initiated whenever a user (or process acting on behalf of a user) accesses an organizational information system. Such user sessions can be terminated (and thus terminate user access) without terminating network sessions.

Session termination terminates all processes associated with a user's logical session except those processes that are specifically created by the user (i.e., session owner) to continue after the session is terminated.

Conditions or trigger events requiring automatic session termination can include, for example, organization-defined periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use.

This capability is typically reserved for specific Ubuntu 24.04 LTS functionality where the system owner, data owner, or organization requires additional assurance."
  desc 'check', 'Verify that all network connections associated with SSH traffic automatically terminate after a period of inactivity with the following command:

$ sudo grep -ir ClientAliveCountMax /etc/ssh/sshd_config*
/etc/ssh/sshd_config:ClientAliveCountMax  1

If "ClientAliveCountMax" is not to "1", if conflicting results are returned, is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to automatically terminate inactive SSH sessions after a period of inactivity.

Modify or append the following line in the "/etc/ssh/sshd_config" file, replacing "[Count]" with a value of 1:

ClientAliveCountMax 1

Restart the SSH daemon for the changes to take effect:

$ sudo systemctl restart ssh.service'
  impact 0.5
  tag check_id: 'C-74775r1066713_chk'
  tag severity: 'medium'
  tag gid: 'V-270742'
  tag rid: 'SV-270742r1066715_rule'
  tag stig_id: 'UBTU-24-600000'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-74676r1066714_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']

  sshdcommand = input('sshdcommand')

  describe command("#{sshdcommand}|&grep -i ClientAliveCountMax") do
    its('stdout.strip') { should cmp 'ClientAliveCountMax 1' }
  end
end
