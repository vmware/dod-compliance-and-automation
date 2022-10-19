control 'HZNV-8X-000124' do
  title 'The Horizon Connection Server must reauthenticate users after a network interruption.'
  desc  'Given the remote access nature of Horizon Connection Server, the client must be ensured to be under positive control as much as is possible from the server side. As such, whenever a network interruption causes a client disconnect, that session must be reauthenticated upon reconnection. To allow a session resumption would be convenient but would allow for the possibility of the endpoint being taken out of the control of the intended user and reconnected from a different location, under the control of a bad actor who could then resume the disconnected session.'
  desc  'rationale', ''
  desc  'check', "
    Log in to the Horizon Connection Server administrative console.

    From the left pane, navigate to Settings >> Global Settings.

    In the right pane, click the \"Security Settings\" tab.

    If the \"Reauthenticate Secure Tunnel Connections After Network Interruption\" value is set to \"No\", this is a finding.
  "
  desc  'fix', "
    Log in to the Horizon Connection Server administrative console.

    From the left pane, navigate to Settings >> Global Settings.

    In the right pane, click the \"Security Settings\" tab.

    Click \"Edit\".

    Check the box next to \"Reauthenticate Secure Tunnel Connections After Network Interruption\".

    Click \"OK\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNV-8X-000124'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  horizonhelper.setconnection

  result = horizonhelper.getpowershellrestwithtoken('rest/config/v1/settings/security')

  json = JSON.parse(result.stdout)

  describe json['re_auth_secure_tunnel_after_interruption'] do
    it { should cmp true }
  end
end
