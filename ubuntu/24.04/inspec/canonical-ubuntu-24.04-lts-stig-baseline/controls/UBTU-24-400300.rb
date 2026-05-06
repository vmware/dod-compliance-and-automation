control 'UBTU-24-400300' do
  title 'Ubuntu 24.04 LTS must enforce 24 hours/1 day as the minimum password lifetime. Passwords for new users must have a 24 hours/1 day minimum password lifetime restriction.'
  desc "Enforcing a minimum password lifetime helps to prevent repeated password changes to defeat the password reuse or history enforcement requirement. If users are allowed to immediately and continually change their password, then the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse.

"
  desc 'check', 'Verify Ubuntu 24.04 LTS enforces a 24 hours/1 day minimum password lifetime for new user accounts with the following command:

$ grep -i ^PASS_MIN_DAYS /etc/login.defs
PASS_MIN_DAYS    1

If the "PASS_MIN_DAYS" parameter value is less than "1" or is commented out, this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to enforce a 24 hours/1 day minimum password lifetime.

Add or modify the following line in the "/etc/login.defs" file:

PASS_MIN_DAYS    1'
  impact 0.5
  tag check_id: 'C-74763r1066677_chk'
  tag severity: 'medium'
  tag gid: 'V-270730'
  tag rid: 'SV-270730r1066679_rule'
  tag stig_id: 'UBTU-24-400300'
  tag gtitle: 'SRG-OS-000075-GPOS-00043'
  tag fix_id: 'F-74664r1066678_fix'
  tag satisfies: ['SRG-OS-000075-GPOS-00043', 'SRG-OS-000730-GPOS-00190']
  tag 'documentable'
  tag cci: ['CCI-004065', 'CCI-004066']
  tag nist: ['IA-5 (1) (g)', 'IA-5 (1) (h)']

  describe login_defs do
    its('PASS_MIN_DAYS') { should cmp >= 1 }
  end
end
