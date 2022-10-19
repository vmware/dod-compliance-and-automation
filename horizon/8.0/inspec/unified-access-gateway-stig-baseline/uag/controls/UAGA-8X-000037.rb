control 'UAGA-8X-000037' do
  title 'The UAG must uniquely identify and authenticate organizational users.'
  desc  "
    To ensure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system. Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors).

    The UAG proxies the authentication, and ultimately the connection, to a Horizon Connection Server. The Horizon Connection Server is responsible for authenticating the user against an Active Directory domain, and ultimately providing the appropriate access level to the user.

    This control is to check whether the Horizon Connection Server has been configured in the UAG settings.

    If the UAG is not intended to provide Horizon services, but is utilized for other services in the environment, this control is not applicable.
  "
  desc  'rationale', ''
  desc  'check', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to General Settings >> Edge Service Settings >> Toggle the icon to \"Show\">> Click the gear icon for \"Horizon Settings\".

    Ensure the \"Enable Horizon\" toggle is enabled.

    If the \"Connection Server URL\" is not configured with the correct Horizon Connection Server information, this is a finding.

    If the UAG is not intended to provide Horizon services, but is utilized for other services in the environment, this control is not applicable.
  "
  desc 'fix', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to General Settings >> Edge Service Settings >> Toggle the icon to \"Show\">> Click the gear icon for \"Horizon Settings\".

    Ensure the \"Enable Horizon\" toggle is enabled.

    Ensure the \"Connection Server URL\" is configured with the correct Horizon Connection Server information.

    Click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000138-ALG-000063'
  tag satisfies: ['SRG-NET-000138-ALG-000088', 'SRG-NET-000138-ALG-000089', 'SRG-NET-000169-ALG-000102']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'UAGA-8X-000037'
  tag cci: ['CCI-000764', 'CCI-000804']
  tag nist: ['IA-2', 'IA-8']

  result = uaghelper.runrestcommand('rest/v1/config/settings')

  describe result do
    its('status') { should cmp 200 }
  end

  unless result.status != 200
    jsoncontent = json(content: result.body)
    svclist = jsoncontent['edgeServiceSettingsList']['edgeServiceSettingsList']

    found = false
    svclist.each do |svc|
      next unless svc['identifier'] == 'VIEW'
      found = true
      describe svc['proxyDestinationUrl'] do
        it { should include input('connectionserver') }
      end
    end

    unless found
      describe 'No Connection Server configuration found' do
        subject { found }
        it { should cmp true }
      end
    end
  end
end
