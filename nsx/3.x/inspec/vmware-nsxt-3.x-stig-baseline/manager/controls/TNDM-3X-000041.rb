control 'TNDM-3X-000041' do
  title 'The NSX-T Manager must enforce a minimum 15-character password length.'
  desc  "
    Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password.

    The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.
  "
  desc  'rationale', ''
  desc  'check', "
    From an NSX-T Manager shell, run the following command(s):

    > get auth-policy minimum-password-length

    Expected result:
    15 characters

    If the output does not match the expected result, or is greater than 15, this is a finding.
  "
  desc 'fix', "
    From an NSX-T Manager shell, run the following command(s):

    > set auth-policy minimum-password-length 15
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000164-NDM-000252'
  tag gid: 'V-251780'
  tag rid: 'SV-251780r810343_rule'
  tag stig_id: 'TNDM-3X-000041'
  tag fix_id: 'F-55194r810342_fix'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']

  result = http("https://#{input('nsxManager')}/api/v1/node/aaa/auth-policy",
                method: 'GET',
                headers: {
                  'Accept' => 'application/json',
                  'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                  'Cookie' => "#{input('sessionCookieId')}",
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
