control 'NMGR-4X-000043' do
  title 'The NSX Manager must enforce password complexity by requiring that at least one special character be used for local accounts.'
  desc '
    Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

    Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

    Multifactor authentication (MFA) is required for all administrative and user accounts on network devices, except for an account of last resort and (where applicable) a root account. Passwords should only be used when MFA using PKI is not available, and for the account of last resort and root account.
  '
  desc 'check', 'From an NSX Manager shell, run the following command:

>  get password-complexity

If the minimum special characters is not 1 or more, this is a finding.

Note: If a maximum number of special characters has been configured, a minimum will not be shown.'
  desc 'fix', '
    From an NSX Manager shell, run the following command:

    > set password-complexity special-chars -1

    Note: Negative numbers indicate a minimum number of characters.
  '
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000169-NDM-000257'
  tag gid: 'V-263214'
  tag rid: 'SV-263214r977409_rule'
  tag stig_id: 'NMGR-4X-000043'
  tag cci: ['CCI-001619']
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
      its('special_chars') { should cmp <= -1 }
    end
  end
end
