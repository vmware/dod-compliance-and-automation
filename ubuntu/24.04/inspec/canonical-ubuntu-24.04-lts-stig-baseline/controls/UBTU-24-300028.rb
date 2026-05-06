control 'UBTU-24-300028' do
  title 'Ubuntu 24.04 LTS must not allow accounts configured in Pluggable Authentication Modules (PAM) with blank or null passwords.'
  desc 'If an account has an empty password, anyone could log on and run commands with the privileges of that account. Accounts with empty passwords must never be used in operational environments.'
  desc 'check', 'To verify null passwords cannot be used, run the following command:

$ grep nullok /etc/pam.d/common-password /etc/pam.d/common-auth

If this produces any output, this is a finding.'
  desc 'fix', 'If an account is configured for password authentication but does not have an assigned password, it is possible to log on to the account without authenticating.

Remove any instances of the "nullok" option in "/etc/pam.d/common-password" to prevent logons with empty passwords.'
  impact 0.7
  tag check_id: 'C-74747r1134807_chk'
  tag severity: 'high'
  tag gid: 'V-270714'
  tag rid: 'SV-270714r1134808_rule'
  tag stig_id: 'UBTU-24-300028'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-74648r1066630_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  common_password_file = input('common_password_file')
  common_auth_file = input('common_auth_file')

  describe file(common_password_file) do
    its('content') { should_not match(/\bnullok\b/) }
  end

  describe file(common_auth_file) do
    its('content') { should_not match(/\bnullok\b/) }
  end
end
