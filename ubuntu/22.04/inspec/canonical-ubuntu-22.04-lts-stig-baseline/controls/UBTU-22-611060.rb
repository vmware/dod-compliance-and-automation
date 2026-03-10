control 'UBTU-22-611060' do
  title 'Ubuntu 22.04 LTS must not allow accounts configured with blank or null passwords.'
  desc 'If an account has an empty password, anyone could log on and run commands with the privileges of that account. Accounts with empty passwords must never be used in operational environments.'
  desc 'check', 'Verify that null passwords cannot be used. Run the following command:

     $ grep nullok /etc/pam.d/common-auth /etc/pam.d/common-password

If this produces any output, this is a finding.'
  desc 'fix', 'Remove any instances of the "nullok" option in "/etc/pam.d/common-password" to prevent logons with empty passwords.

Remove any instances of the "nullok" option in "/etc/pam.d/common-auth" and "/etc/pam.d/common-password".'
  impact 0.7
  tag check_id: 'C-64299r1082231_chk'
  tag severity: 'high'
  tag gid: 'V-260570'
  tag rid: 'SV-260570r1082233_rule'
  tag stig_id: 'UBTU-22-611060'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-64207r1082232_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe command(' grep nullok /etc/pam.d/common-auth') do
    its('stdout') { should match '' }
  end
  describe command(' grep nullok /etc/pam.d/common-password') do
    its('stdout') { should match '' }
  end
end
