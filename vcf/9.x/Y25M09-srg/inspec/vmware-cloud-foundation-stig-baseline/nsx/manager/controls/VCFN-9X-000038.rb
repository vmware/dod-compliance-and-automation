control 'VCFN-9X-000038' do
  title 'The VMware Cloud Foundation NSX Manager must enforce a minimum 15-character password length for local accounts.'
  desc  "
    Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password.

    The shorter the password, the lower the number of possible combinations that must be tested before the password is compromised. Use of more characters in a password helps to increase exponentially the time and/or resources required to compromise the password.
  "
  desc  'rationale', ''
  desc  'check', "
    From an NSX Manager shell, run the following NSX CLI command:

    >  get password-complexity

    If the minimum password length is not 15 or greater, this is a finding.
  "
  desc 'fix', "
    From an NSX Manager shell, run the following NSX CLI command:

    > set password-complexity minimum-password-length 15
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000164-NDM-000252'
  tag satisfies: ['SRG-APP-000860-NDM-000250']
  tag gid: 'V-VCFN-9X-000038'
  tag rid: 'SV-VCFN-9X-000038'
  tag stig_id: 'VCFN-9X-000038'
  tag cci: ['CCI-004064', 'CCI-004066']
  tag nist: ['IA-5 (1) (f)', 'IA-5 (1) (h)']

  result = http("https://#{input('nsx_managerAddress')}/api/v1/node/aaa/auth-policy",
                method: 'GET',
                headers: {
                  'Accept' => 'application/json',
                  'X-XSRF-TOKEN' => "#{input('nsx_sessionToken')}",
                  'Cookie' => "#{input('nsx_sessionCookieId')}"
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
