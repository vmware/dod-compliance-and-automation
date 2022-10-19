control 'UAGA-8X-000014' do
  title 'The UAG must limit the number of concurrent user sessions to an organization-defined number.'
  desc  'Network element management includes the ability to control the number of users and user sessions that utilize a network element. Limiting the number of concurrent sessions per user is helpful in limiting risks related to DoS attacks.'
  desc  'rationale', ''
  desc  'check', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to Advanced Settings >>System Configuration. Click the \"Gear\" icon to edit. Scroll down to the \"Maximum Connections per Session\" field.

    If the \"Maximum Connections per Session\" field is not set to the organization-defined allowed number, this is a finding.

    If the \"Maximum Connections per Session\" field is set to 0 (no limit), this is a finding.

    Note:  A value of 8 or lower causes errors in the Horizon Client. The default value is 16.
  "
  desc 'fix', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to Advanced Settings >> System Configuration.

    Click the \"Gear\" icon to edit.

    Set the \"Maximum Connections per Session\" value to \"16\".

    Click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000053-ALG-000001'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'UAGA-8X-000014'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']

  result = uaghelper.runrestcommand('rest/v1/config/settings')

  describe result do
    its('status') { should cmp 200 }
  end

  unless result.status != 200
    jsoncontent = json(content: result.body)
    describe jsoncontent['systemSettings']['maxConnectionsAllowedPerSession'] do
      it { should_not cmp 0 }
      it { should be > 8 }
      it { should cmp input('maxConnectionsPerUser') }
    end
  end
end
