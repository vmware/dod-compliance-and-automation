control 'NMGR-4X-000012' do
  title 'The NSX Manager must be configured to enforce the limit of three consecutive invalid logon attempts, after which time it must block any login attempt for 15 minutes.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced.'
  desc 'check', '
    From an NSX Manager shell, run the following commands:

    > get auth-policy api lockout-reset-period

    Expected result:
    900 seconds

    If the output does not match the expected result, this is a finding.

    > get auth-policy api lockout-period

    Expected result:
    900 seconds

    If the output does not match the expected result, this is a finding.

    > get auth-policy api max-auth-failures

    Expected result:
    3

    If the output does not match the expected result, this is a finding.

    > get auth-policy cli lockout-period

    Expected result:
    900 seconds

    If the output does not match the expected result, this is a finding.

    > get auth-policy cli max-auth-failures

    Expected result:
    3

    If the output does not match the expected result, this is a finding.
  '
  desc 'fix', '
    From an NSX Manager shell, run the following commands:

    > set auth-policy api lockout-reset-period 900
    > set auth-policy api lockout-period 900
    > set auth-policy api max-auth-failures 3
    > set auth-policy cli lockout-period 900
    > set auth-policy cli max-auth-failures 3
  '
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000065-NDM-000214'
  tag gid: 'V-263204'
  tag rid: 'SV-263204r977379_rule'
  tag stig_id: 'NMGR-4X-000012'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']

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
      its('api_failed_auth_reset_period') { should cmp '900' }
      its('api_failed_auth_lockout_period') { should cmp '900' }
      its('api_max_auth_failures') { should cmp '3' }
      its('cli_failed_auth_lockout_period') { should cmp '900' }
      its('cli_max_auth_failures') { should cmp '3' }
    end
  end
end
