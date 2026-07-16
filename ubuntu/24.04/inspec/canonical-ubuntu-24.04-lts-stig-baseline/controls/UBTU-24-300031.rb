control 'UBTU-24-300031' do
  title 'Ubuntu 24.04 LTS must not allow unattended or automatic login via SSH.'
  desc 'Failure to restrict system access to authenticated users negatively impacts Ubuntu 24.04 LTS security.'
  desc 'check', %q(Verify unattended or automatic login via SSH is disabled with the following command:

$ egrep -r '(Permit(.*?)(Passwords|Environment))' /etc/ssh/sshd_config
PermitEmptyPasswords no
PermitUserEnvironment no

If the "PermitEmptyPasswords" or "PermitUserEnvironment" keywords are set to a value other than "no", are commented out, are both missing, or conflicting results are returned, this is a finding.)
  desc 'fix', 'Configure Ubuntu 24.04 LTS to allow the SSH daemon to not allow unattended or automatic login to the system.

Add or edit the following lines in the "/etc/ssh/sshd_config" file:

PermitEmptyPasswords no
PermitUserEnvironment no

Restart the SSH daemon for the changes to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.7
  tag check_id: 'C-74750r1067177_chk'
  tag severity: 'high'
  tag gid: 'V-270717'
  tag rid: 'SV-270717r1067177_rule'
  tag stig_id: 'UBTU-24-300031'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-74651r1066639_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  sshdcommand = input('sshdcommand')

  describe command("#{sshdcommand}|&grep -i PermitEmptyPasswords") do
    its('stdout.strip') { should cmp 'PermitEmptyPasswords no' }
  end
  describe command("#{sshdcommand}|&grep -i PermitUserEnvironment") do
    its('stdout.strip') { should cmp 'PermitUserEnvironment no' }
  end
end
