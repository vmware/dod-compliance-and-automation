control 'HZNV-8X-000130' do
  title 'The Horizon Connection Server must discard SSO credentials after 15 minutes.'
  desc  'Horizon Connection Server caches user credentials temporarily to ensure that the user can connect to their desktop pools without reauthenticating, right after logging in to the broker. However, this grace period must be restricted so that SSO credentials are only retained for 15 minutes before being discarded. Subsequent desktop connection attempts must require reauthentication, even if the user is still connected to the broker.'
  desc  'rationale', ''
  desc  'check', "
    Log in to the Horizon Connection Server administrative console.

    From the left pane, navigate to Settings >> Global Settings.

    In the right pane, click the \"General Settings\" tab.

    Locate the \"Discard SSO credentials\" setting.

    If the \"Discard SSO Credentials\" setting is set to \"Never\", or the value of \"Discard SSO Credentials\" is set to anything greater than 15 minutes, this is a finding.
  "
  desc  'fix', "
    Log in to the Horizon Connection Server administrative console.

    From the left pane, navigate to Settings >> Global Settings.

    In the right pane, click the \"General Settings\" tab.

    Click \"Edit\".

    Next to \"Discard SSO Credentials\", select \"After\" from the dropdown and fill in \"15\" in the minutes text field.

    Click \"OK\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNV-8X-000130'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  horizonhelper.setconnection

  result = horizonhelper.getpowershellrestwithtoken('rest/config/v1/settings/general')

  json = JSON.parse(result.stdout)

  describe json['machine_sso_timeout_policy'] do
    it { should cmp 'DISABLED_AFTER' }
  end

  describe json['machine_sso_timeout_minutes'] do
    it { should cmp <= 15 }
  end
end
