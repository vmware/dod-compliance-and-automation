control 'HZNV-8X-000128' do
  title 'The Horizon Connection Server must disconnect users after a maximum of ten hours.'
  desc  'Horizon Connection Server is intended to provide remote desktops and applications, generally during working hours, and for no more than an extended workday. Leaving sessions active for more than what is reasonable for a work day opens the possibility of a session becoming unoccupied and insecure on the client side. For example, if a client connection is opened at 0900, there are few day-to-day reasons that the connection should still be open after 1900; therefore the connection must be terminated. If the user is still active, they can reauthenticate immediately and continue the session for another ten hours.'
  desc  'rationale', ''
  desc  'check', "
    Log in to the Horizon Connection Server administrative console.

    From the left pane, navigate to Settings >> Global Settings.

    In the right pane, click the \"General Settings\" tab and locate the \"Forcibly Disconnect Users\" setting.

    If the \"Forcibly Disconnect Users\" setting is set to \"Never\", or the value of \"Forcibly Disconnect Users\" is set to anything greater than \"600\" minutes (ten hours), this is a finding.
  "
  desc  'fix', "
    Log in to the Horizon Connection Server administrative console.

    From the left pane, navigate to Settings >> Global Settings.

    In the right pane, click the \"General Settings\" tab.

    Click \"Edit\".

    Next to \"Forcibly Disconnect Users\", select \"After\" from the dropdown and fill in \"600\" minutes in the text field.

    Click \"OK\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNV-8X-000128'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  horizonhelper.setconnection

  result = horizonhelper.getpowershellrestwithtoken('rest/config/v1/settings/general')

  json = JSON.parse(result.stdout)

  describe json['client_max_session_timeout_minutes'] do
    it { should cmp <= 600 }
  end
end
