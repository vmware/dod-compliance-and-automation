control 'HZNV-8X-000132' do
  title 'The Horizon Connection Server must require DoD PKI for client logins.'
  desc  "
    Before clients can select a desktop or application to access, they must first authenticate to the broker, which is the Connection Server itself. If the client is accessing the broker directly, then the allowed authentication methods must be specified. These include RADIUS, SecurID, username/password and smart card.

    In the DoD, CAC login must be enforced at all times, for all client connections.

    If the client is connecting through the UAG appliance, this requirement does not apply.
  "
  desc  'rationale', ''
  desc  'check', "
    Log in to the Horizon Connection Server administrative console.

    From the left pane, navigate to Settings >> Servers.

    In the right pane, select the \"Connection Servers\" tab.

    For each Connection Server listed, select the server and click \"Edit\".

    Click the \"Authentication\" tab, then under \"Horizon Authentication\", find the value in the dropdown below \"Smart card authentication for users\".

    If \"Smart card authentication for users\" is set to \"Optional\" or \"Not Allowed\", a SAML Authenticator must be configured, and that external IdP must be configured to require CAC authentication. If these requirements are not met, this is a finding.

    If \"Smart card authentication for users\" is set to \"Required\" on each of the listed Connection Servers, this is not a finding.

    If the Connection Server is paired with a Unified Access Gateway (UAG) that is performing authentication, this requirement is not applicable.

    NOTE: If another form of DoD approved PKI is used, and configured to be required for client logins, this is not a finding.
  "
  desc 'fix', "
    Option One - Use Horizon's native CAC authentication:

    > Log in to the Horizon Connection Server administrative console.

    > From the left pane, navigate to Settings >> Servers.

    > In the right pane, select the \"Connection Servers\" tab.

    > For each Connection Server listed, select the server and click \"Edit\".

    > Click the \"Authentication\" tab, then under \"Horizon Authentication\", in the dropdown below \"Smart card authentication for users\", select \"Required\".

    > Click \"OK\".

    Option Two - Delegate CAC authentication to an external IdP:

    > Log in to the Horizon Connection Server administrative console.

    > From the left pane, navigate to Settings >> Servers.

    > In the right pane, select the \"Connection Servers\" tab.

    > For each Connection Server listed, select the server and click \"Edit\".

    > Click the \"Authentication\" tab, then under \"Horizon Authentication\", in the dropdown next to \"Smart card authentication for users\", select \"Optional\" or \"Not Allowed\".

    > In the dropdown under \"Delegation of authentication to VMware Horizon (SAML 2.0 Authenticator)\", select \"Allowed\" or \"Required\", depending on what you set the native capability to in the previous step.

    > Click \"Manage SAML Authenticators\".

    > Click \"Add\", then complete the necessary fields.

    > Ensure \"Enabled for Connection Server\" is checked, then click \"OK\" on each subsequent screen to save the settings.

    Restart the \"VMware Horizon View Connection Server\" service for changes to take effect.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNV-8X-000132'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  horizonhelper.setconnection

  result = horizonhelper.getpowershellrestwithsession('view-vlsi/rest/v1/ConnectionServer/list')

  cslist = JSON.parse(result.stdout)

  cslist['value'].each do |cs|
    if cs['general']['fqhn'].upcase == horizonhelper.getinput('fqdn').upcase
      describe 'CS fqdn matched - ' + cs['general']['fqhn'] do
        subject { cs['authentication']['smartCardSupport'] }
        it { should cmp 'ON' }
      end
    else
      describe 'CS not matched - ' + cs['general']['fqhn'] do
        skip 'CS fqdn not matched - ' + cs['general']['fqhn']
      end
    end
  end
end
