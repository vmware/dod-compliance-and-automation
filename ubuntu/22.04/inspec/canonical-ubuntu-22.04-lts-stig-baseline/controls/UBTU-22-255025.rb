control 'UBTU-22-255025' do
  title 'Ubuntu 22.04 LTS must not allow unattended or automatic login via SSH.'
  desc 'Failure to restrict system access to authenticated users negatively impacts Ubuntu 22.04 LTS security.'
  desc 'check', %q(Verify that unattended or automatic login via SSH is disabled by using the following command:

     $ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iEH '(permit(.*?)(passwords|environment))'
     /etc/ssh/sshd_config:PermitEmptyPasswords no
     /etc/ssh/sshd_config:PermitUserEnvironment no

If "PermitEmptyPasswords" and "PermitUserEnvironment" are not set to "no", are commented out, are missing, or conflicting results are returned, this is a finding.)
  desc 'fix', 'Configure the SSH server to not allow unattended or automatic login to the system.

Add or modify the following lines in the "/etc/ssh/sshd_config" file:

PermitEmptyPasswords no
PermitUserEnvironment no

Restart the SSH daemon for the changes to take effect:

     $ sudo systemctl restart sshd.service'
  impact 0.7
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64255r953389_chk'
  tag severity: 'high'
  tag gid: 'V-260526'
  tag rid: 'SV-260526r991591_rule'
  tag stig_id: 'UBTU-22-255025'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-64163r953390_fix'
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
