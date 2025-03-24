control 'NMGR-4X-000039' do
  title 'The NSX Manager must enforce a minimum 15-character password length for local accounts.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password.

The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'From an NSX Manager shell, run the following command:

>  get password-complexity

If the minimum password length is not 15 or greater, this is a finding.'
  desc 'fix', 'From an NSX Manager shell, run the following command:

> set password-complexity minimum-password-length 15'
  impact 0.5
  ref 'DPMS Target VMware NSX 4.x Manager NDM'
  tag check_id: 'C-69233r994169_chk'
  tag severity: 'medium'
  tag gid: 'V-265316'
  tag rid: 'SV-265316r994171_rule'
  tag stig_id: 'NMGR-4X-000039'
  tag gtitle: 'SRG-APP-000164-NDM-000252'
  tag fix_id: 'F-69141r994170_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']

  result = http("https://#{input('nsxManager')}/api/v1/node/aaa/auth-policy",
                method: 'GET',
                headers: {
                  'Accept' => 'application/json',
                  'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                  'Cookie' => "#{input('sessionCookieId')}"
                },
                ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    describe json(content: result.body) do
      its('minimum_password_length') { should cmp >= 15 }
    end
  end
end
