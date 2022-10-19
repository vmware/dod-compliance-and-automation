control 'UAGA-8X-000162' do
  title 'The UAG local monitoring accounts must be configured with a password maximum lifetime of 90 days or less.'
  desc  'Any password, no matter how complex, can eventually be deduced. If the application does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the passwords and related accounts could be compromised. One method of minimizing this risk is to force users to use complex passwords and periodically change them. '
  desc  'rationale', ''
  desc  'check', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to Advanced Settings >> System Configuration.

    Click the \"Gear\" icon to check the settings.

    If the \"Monitoring User Password Age\" is set to 0, or is set to a value greater than 90, this is a finding.
  "
  desc 'fix', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to Advanced Settings >> System Configuration.

    Click the \"Gear\" icon to check the settings.

    Ensure the \"Monitoring User Password Age\" is set to \"90\".

    Click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000512-ALG-000062'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'UAGA-8X-000162'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  result = uaghelper.runrestcommand('rest/v1/config/system')

  describe result do
    its('status') { should cmp 200 }
  end

  unless result.status != 200
    jsoncontent = json(content: result.body)
    describe jsoncontent['monitoringUsersPasswordExpirationDays'] do
      it { should (be > 0).and(be <= 90) }
    end
  end
end
