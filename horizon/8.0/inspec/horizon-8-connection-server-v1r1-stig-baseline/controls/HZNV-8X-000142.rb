control 'HZNV-8X-000142' do
  title 'The Horizon Connection Server must require CAC reauthentication after user idle timeouts.'
  desc  'If a user VDI session times out due to inactivity, the user must be assumed not to be active and their resources must be locked. These resources should only be made available again upon the user reauthenticating, versus reusing the initial connection. This ensures that the connection has not been hijacked and re-establishes nonrepudiation.'
  desc  'rationale', ''
  desc  'check', "
    Log in to the Horizon Connection Server Console.

    From the left pane, navigate to Settings >> Global Settings.

    In the right pane, click the \"General Settings\" tab.

    If the value of \"Enable 2-Factor Reauthentication\" is set to \"No\", this is a finding.
  "
  desc  'fix', "
    Log in to the Horizon Connection Server Console.

    From the left pane, navigate to Settings >> Global Settings.

    In the right pane, click the \"General Settings\" tab.

    Click \"Edit\".

    Select the checkbox next to \"Enable 2-Factor Reauthentication\".

    Click \"OK\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNV-8X-000142'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  horizonhelper.setconnection

  result = horizonhelper.getpowershellrestwithtoken('rest/config/v1/settings/general')

  gensettings = JSON.parse(result.stdout)

  describe 'Checking if multifactor reauthentication is enabled' do
    subject { gensettings['enable_multi_factor_re_authentication'] }
    it { should cmp true }
  end
end
