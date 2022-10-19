control 'UAGA-8X-000155' do
  title 'The UAG must not provide environment information to third parties.'
  desc  'Providing technical details about environmental infrastructure to third parties could unknowingly expose sensitive information to bad actors if intercepted.'
  desc  'rationale', ''
  desc  'check', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to Advanced Settings >> System Configuration.

    Click the \"Gear\" icon to check the settings.

    If the \"Join CEIP\" toggle is enabled, this is a finding.
  "
  desc 'fix', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to Advanced Settings >> System Configuration.

    Click the \"Gear\" icon to check the settings.

    Ensure the \"Join CEIP\" toggle is disabled.

    Click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000512-ALG-000062'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'UAGA-8X-000155'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  result = uaghelper.runrestcommand('rest/v1/config/system')

  describe result do
    its('status') { should cmp 200 }
  end

  unless result.status != 200
    jsoncontent = json(content: result.body)
    describe jsoncontent['ceipEnabled'] do
      it { should cmp false }
    end
  end
end
