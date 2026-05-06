control 'UBTU-24-300027' do
  title 'Ubuntu 24.04 LTS must not have accounts configured with blank or null passwords.'
  desc 'If an account has an empty password, anyone could log on and run commands with the privileges of that account. Accounts with empty passwords must never be used in operational environments.'
  desc 'check', %q(Check the "/etc/shadow" file for blank passwords with the following command:

$ sudo awk -F: '!$2 {print $1}' /etc/shadow

If the command returns any results, this is a finding.)
  desc 'fix', 'Configure all accounts on the system to have a password or lock the account with the following commands:

Perform a password reset:
$ sudo passwd [username]

Lock an account:
$ sudo passwd -l [username]'
  impact 0.7
  tag check_id: 'C-74746r1066626_chk'
  tag severity: 'high'
  tag gid: 'V-270713'
  tag rid: 'SV-270713r1066628_rule'
  tag stig_id: 'UBTU-24-300027'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-74647r1066627_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe command("awk -F: '!$2 {print $1}' /etc/shadow") do
    its('stdout') { should match '' }
  end
end
