control 'UAGA-8X-000156' do
  title 'The UAG must have a clock skew tolerance of less than 5 minutes.'
  desc  "
    A typical SAML Assertion process involves a Service Provider (SP) sending an authentication request to an Identity Provider (IdP), receiving a SAML response from the IdP, and validating the information contained in the response.

    Date fields such as \"NotBefore\" and \"NotOnOrAfter\" are contained within the response, and control the time window during which the SAML response is valid.

    If the system clocks of the SP and IdP are not in sync, this may lead to issues with SAML token validation and authentication.

    The UAG contains a \"Clock Skew Tolerance\" field that can help address this issue by setting an allowed number of seconds of allowed clock skew between servers on the same network.
  "
  desc  'rationale', ''
  desc  'check', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to Advanced Settings >> System Configuration.

    Click the \"Gear\" icon to check the settings.

    If the \"Clock Skew Tolerance\" value is greater than 300 (5 minutes), this is a finding.
  "
  desc 'fix', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to Advanced Settings >> System Configuration.

    Click the \"Gear\" icon to check the settings.

    Ensure the \"Clock Skew Tolerance\" value is 300 (5 minutes).

    Click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000512-ALG-000062'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'UAGA-8X-000156'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  result = uaghelper.runrestcommand('rest/v1/config/system')

  describe result do
    its('status') { should cmp 200 }
  end

  unless result.status != 200
    jsoncontent = json(content: result.body)
    describe jsoncontent['clockSkewTolerance'] do
      it { should be <= input('clockSkewTolerance') }
    end
  end
end
