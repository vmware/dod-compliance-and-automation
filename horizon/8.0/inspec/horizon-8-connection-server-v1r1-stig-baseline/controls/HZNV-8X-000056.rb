control 'HZNV-8X-000056' do
  title 'The Horizon Connection Server must time out idle administrative sessions after 15 minutes or less.'
  desc  "
    If communication sessions remain open for extended periods of time, even when unused, there is the potential for an adversary to hijack the session and use it to gain access to the system.

    Horizon Connection Server administrative sessions can and must be limited in the amount of idle time that will be allowed before an automatic logoff occurs. By default, 30 minutes of idle time is allowed, but this must be changed to 15 minutes or less for systems on a DoD network. This configuration must be verified and maintained over time.
  "
  desc  'rationale', ''
  desc  'check', "
    Log in to the Horizon Connection Server administrative console.

    From the left pane, navigate to Settings >> Global Settings.

    In the right pane, click the \"General Settings\" tab.

    If the \"Horizon Console Session Timeout\" value is set to more than 15 minutes, this is a finding.
  "
  desc  'fix', "
    Log in to the Horizon Connection Server administrative console.

    From the left pane, navigate to Settings >> Global Settings.

    In the right pane, click the \"General Settings\" tab.

    Click \"Edit\".

    Set the \"Horizon Console Session Timeout\" value to \"15\" minutes (or less).

    Click \"OK\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000220-AS-000148'
  tag satisfies: ['SRG-APP-000295-AS-000263', 'SRG-APP-000389-AS-000253']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'HZNV-8X-000056'
  tag cci: ['CCI-001185', 'CCI-002038', 'CCI-002361']
  tag nist: ['AC-12', 'IA-11', 'SC-23 (1)']

  horizonhelper.setconnection

  result = horizonhelper.getpowershellrestwithtoken('rest/config/v1/settings/general')

  json = JSON.parse(result.stdout)

  describe json['console_session_timeout_minutes'] do
    it { should cmp <= 15 }
  end
end
