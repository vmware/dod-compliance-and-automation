control 'UBTU-22-411025' do
  title 'Ubuntu 22.04 LTS must enforce 24 hours/one day as the minimum password lifetime. Passwords for new users must have a 24 hours/one day minimum password lifetime restriction.'
  desc "Enforcing a minimum password lifetime helps to prevent repeated password changes to defeat the password reuse or history enforcement requirement. If users are allowed to immediately and continually change their password, then the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse."
  desc 'check', 'Verify Ubuntu 22.04 LTS enforces a 24 hours/one day minimum password lifetime for new user accounts by using the following command:

     $ grep -i pass_min_days /etc/login.defs
     PASS_MIN_DAYS    1

If "PASS_MIN_DAYS" is less than "1", is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to enforce a 24 hours/one day minimum password lifetime.

Add or modify the following line in the "/etc/login.defs" file:

PASS_MIN_DAYS    1'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64274r986278_chk'
  tag severity: 'medium'
  tag gid: 'V-260545'
  tag rid: 'SV-260545r1015007_rule'
  tag stig_id: 'UBTU-22-411025'
  tag gtitle: 'SRG-OS-000075-GPOS-00043'
  tag fix_id: 'F-64182r986279_fix'
  tag 'documentable'
  tag cci: ['CCI-000198', 'CCI-004066']
  tag nist: ['IA-5 (1) (d)', 'IA-5 (1) (h)']

  describe login_defs do
    its('PASS_MIN_DAYS') { should cmp >= 1 }
  end
end
