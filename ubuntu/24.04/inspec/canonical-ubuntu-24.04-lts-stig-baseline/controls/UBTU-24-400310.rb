control 'UBTU-24-400310' do
  title 'Ubuntu 24.04 LTS must enforce a 60-day maximum password lifetime restriction. Passwords for new users must have a 60-day maximum password lifetime restriction.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If Ubuntu 24.04 LTS does not limit the lifetime of passwords and force users to change their passwords, there is the risk that Ubuntu 24.04 LTS passwords could be compromised.

'
  desc 'check', 'Verify Ubuntu 24.04 LTS enforces a 60-day maximum password lifetime for new user accounts with the following command:

$ grep -i ^PASS_MAX_DAYS /etc/login.defs
PASS_MAX_DAYS    60

If the "PASS_MAX_DAYS" parameter value is less than "60" or is commented out, this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to enforce a 60-day maximum password lifetime.

Add or modify the following line in the "/etc/login.defs" file:

PASS_MAX_DAYS    60'
  impact 0.5
  tag check_id: 'C-74764r1066680_chk'
  tag severity: 'medium'
  tag gid: 'V-270731'
  tag rid: 'SV-270731r1066682_rule'
  tag stig_id: 'UBTU-24-400310'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag fix_id: 'F-74665r1066681_fix'
  tag satisfies: ['SRG-OS-000076-GPOS-00044', 'SRG-OS-000730-GPOS-00190']
  tag 'documentable'
  tag cci: ['CCI-004065', 'CCI-004066']
  tag nist: ['IA-5 (1) (g)', 'IA-5 (1) (h)']

  describe login_defs do
    its('PASS_MAX_DAYS') { should cmp <= 60 }
  end
end
