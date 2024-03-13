control 'PHTN-30-000027' do
  title 'The Photon operating system must be configured so that passwords for new users are restricted to a 24-hour minimum lifetime.'
  desc "Enforcing a minimum password lifetime helps to prevent repeated password changes to defeat the password reuse or history enforcement requirement. If users are allowed to immediately and continually change their password, the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse."
  desc 'check', 'At the command line, run the following command:

# grep "^PASS_MIN_DAYS" /etc/login.defs

If "PASS_MIN_DAYS" is not set to "1", this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/login.defs

Modify the "PASS_MIN_DAYS" line to the following:

PASS_MIN_DAYS   1'
  impact 0.5
  tag check_id: 'C-60179r887184_chk'
  tag severity: 'medium'
  tag gid: 'V-256504'
  tag rid: 'SV-256504r887186_rule'
  tag stig_id: 'PHTN-30-000027'
  tag gtitle: 'SRG-OS-000075-GPOS-00043'
  tag fix_id: 'F-60122r887185_fix'
  tag cci: ['CCI-000198']
  tag nist: ['IA-5 (1) (d)']

  describe login_defs do
    its('PASS_MIN_DAYS') { should cmp '1' }
  end
end
