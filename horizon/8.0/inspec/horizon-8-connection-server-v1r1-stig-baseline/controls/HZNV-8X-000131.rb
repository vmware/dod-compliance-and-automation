control 'HZNV-8X-000131' do
  title 'The Horizon Connection Server must not accept pass-through client credentials.'
  desc  "
    Horizon Connection Server has the ability to allow clients to authenticate using the local session credentials of their local endpoint.

    While convenient, this must be disabled for DoD deployments because of several reasons, including the server cannot ascertain the method of endpoint login and whether that user's client certificate has since been revoked.
  "
  desc  'rationale', ''
  desc  'check', "
    Log in to the Horizon Connection Server administrative console.

    From the left pane, navigate to Settings >> Servers.

    In the right pane, select the \"Connection Servers\" tab.

    For each Connection Server listed, select the server and click \"Edit\".

    Click the \"Authentication\" tab.

    Scroll down to the \"Current User Authentication\" and note the \"Accept logon as current user\" checkbox.

    If the \"Accept logon as current user\" checkbox is checked, this is a finding.

    Note: If \"Smart card authentication for users\" is set to \"Required\", this setting is automatically disabled and greyed out, and this control would be not applicable.
  "
  desc  'fix', "
    Log in to the Horizon Connection Server administrative console.

    From the left pane, navigate to Settings >> Servers.

    Select the Connection Servers tab in the right pane.

    Click \"Edit\".

    Click the \"Authentication\" tab.

    Scroll down to the \"Current User Authentication\".

    Uncheck the checkbox next to \"Accept logon as current user\".

    Click \"OK\".

    Note: When \"Smart card authentication for users\" is set to \"Required\", this setting will be unchecked and greyed out automatically.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNV-8X-000131'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  horizonhelper.setconnection

  result = horizonhelper.getpowershellrestwithsession('view-vlsi/rest/v1/ConnectionServer/list')

  cslist = JSON.parse(result.stdout)

  cslist['value'].each do |cs|
    if cs['general']['fqhn'].upcase == horizonhelper.getinput('fqdn').upcase
      describe 'CS fqdn matched - ' + cs['general']['fqhn'] + ' - checking SPN setting' do
        subject { cs['general']['discloseServicePrincipalName'] }
        it { should cmp false }
      end
      describe 'CS fqdn matched - ' + cs['general']['fqhn'] + ' - checking pass-thru' do
        subject { cs['authentication']['gssAPIConfig'] }
        it { should include 'gssAPIEnabled=False' }
      end
    else
      describe 'CS not matched - ' + cs['general']['fqhn'] do
        skip 'CS fqdn not matched - ' + cs['general']['fqhn']
      end
    end
  end
end
