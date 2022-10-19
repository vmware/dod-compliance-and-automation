control 'UAGA-8X-000040' do
  title 'The UAG must use multifactor authentication for network access to non-privileged accounts.'
  desc  "
    Without the use of multifactor authentication, the ease of access to privileged functions is greatly increased.

    Multifactor authentication requires using two or more factors to achieve authentication.

    Factors include:

    (i) something a user knows (e.g., password/PIN);
    (ii) something a user has (e.g., cryptographic identification device, token); or
    (iii) something a user is (e.g., biometric).

    To ensure accountability and prevent unauthenticated access, non-privileged users must utilize multifactor authentication to prevent potential misuse and compromise of the system.

    Authenticating with a PKI credential and entering the associated PIN is an example of multifactor authentication.
  "
  desc  'rationale', ''
  desc  'check', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to General Settings >> Edge Service Settings >> Toggle the icon to \"Show\" >> Click the gear icon for \"Horizon Settings\" >> Click \"More\" to expand the settings.

    Under \"Auth Methods\", ensure the value set is \"X.509 Certificate\".

    If the value of \"Auth Methods\" is anything other than \"X.509 Certificate\", this is a finding.
  "
  desc 'fix', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to General Settings >> Edge Service Settings >> Toggle the icon to \"Show\" >> Click the gear icon for \"Horizon Settings\" >> Click \"More\" to expand the settings.

    Under \"Auth Methods\", ensure the value set is \"X.509 Certificate\".

    Click \"Save\".

    Note: In order for the UAG to handle certificate authentication, SAML connectivity must be configured between the UAG and the Horizon Connection Server.  Please see the VMware documentation for details.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000140-ALG-000094'
  tag satisfies: ['SRG-NET-000339-ALG-000090']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'UAGA-8X-000040'
  tag cci: ['CCI-000766', 'CCI-001951']
  tag nist: ['IA-2 (11)', 'IA-2 (2)']

  result = uaghelper.runrestcommand('rest/v1/config/edgeservice')

  describe result do
    its('status') { should cmp 200 }
  end

  unless result.status != 200
    jsoncontent = json(content: result.body)
    svclist = jsoncontent['edgeServiceSettingsList']

    svclist.each do |svc|
      next unless svc['identifier'] == 'VIEW'
      describe 'Checking Auth Methods for Connection Server' do
        subject { svc['authMethods'] }
        it { should cmp 'certificate-auth' }
      end
    end
  end
end
