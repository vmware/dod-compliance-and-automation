control 'CDAP-10-000130' do
  title 'Cloud Director must enable account lockout for unsuccessful login attempts.'
  desc  'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account.'
  desc  'rationale', ''
  desc  'check', "
    From the Cloud Director provider interface, go to Administration >> Settings >> Password Policy.

    View the \"Account Lockout\" policy.

    If \"Account Lockout\" is not enabled, this is a finding.

    If \"Invalid logins before lockout\" is not set to 3 or less, this is a finding.

    If \"Account lockout interval\" is not 15 minutes or less, this is a finding.
  "
  desc 'fix', "
    From the Cloud Director provider interface, go to Administration >> Settings >> Password Policy.

    Click Edit.

    Enable the radio button next to \"Account Logout\"

    Configure the \"Invalid logins before lockout\" setting to 3.

    Configure the \"Account lockout interval\" to 15 minutes or less.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-CDAP-10-000130'
  tag rid: 'SV-CDAP-10-000130'
  tag stig_id: 'CDAP-10-000130'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  result = http("https://#{input('vcdURL')}/api/admin/extension/settings/passwordPolicy",
                method: 'GET',
                headers: {
                  'accept' => "#{input('legacyApiVersion')}",
                  'Authorization' => "#{input('bearerToken')}"
                },
                ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    describe json(content: result.body) do
      its(['accountLockoutEnabled']) { should cmp 'true' }
      its(['invalidLoginsBeforeLockout']) { should cmp <= 3 }
      its(['accountLockoutIntervalMinutes']) { should cmp <= 15 }
    end
  end
end
