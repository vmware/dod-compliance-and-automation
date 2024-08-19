control 'NMGR-4X-000040' do
  title 'The NSX Manager must enforce password complexity by requiring that at least one uppercase character be used for local accounts.'
  desc 'Use of a complex passwords helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password is, the greater the number of possible combinations that need to be tested before the password is compromised.

Multifactor authentication (MFA) is required for all administrative and user accounts on network devices, except for an account of last resort and (where applicable) a root account. Passwords should only be used when MFA using public key infrastructure (PKI) is not available, and for the account of last resort and root account.'
  desc 'check', '
    From an NSX Manager shell, run the following command:

    >  get password-complexity

    If the minimum uppercase characters is not 1 or more, this is a finding.

    Note: If a maximum number of uppercase characters has been configured a minimum will not be shown.
  '
  desc 'fix', '
    From an NSX Manager shell, run the following command:

    > set password-complexity upper-chars -1

    Note: Negative numbers indicate a minimum number of characters.
  '
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000166-NDM-000254'
  tag gid: 'V-263211'
  tag rid: 'SV-263211r977400_rule'
  tag stig_id: 'NMGR-4X-000040'
  tag cci: ['CCI-000192']
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
      its('upper_chars') { should cmp <= -1 }
    end
  end
end
