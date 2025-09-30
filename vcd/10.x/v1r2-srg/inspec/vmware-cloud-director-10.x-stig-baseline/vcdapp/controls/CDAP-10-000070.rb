control 'CDAP-10-000070' do
  title 'Cloud Director must automatically terminate an idle user session after 15 minutes.'
  desc  "
    An attacker can take advantage of user sessions that are left open, thus bypassing the user authentication process.

    To thwart the vulnerability of open and unused user sessions, the application server must be configured to close the sessions when a configured condition or trigger event is met.

    Session termination terminates all processes associated with a user's logical session except those processes that are specifically created by the user (i.e., session owner) to continue after the session is terminated.

    Conditions or trigger events requiring automatic session termination can include, for example, periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use.
  "
  desc  'rationale', ''
  desc  'check', "
    From the Cloud Director provider interface, go to Administration >> Settings >> General >> Timeouts.

    Review the Idle session timeout value.

    If the \"Idle session timeout\" is not set to 15 minutes or less, this is a finding.
  "
  desc 'fix', "
    From the Cloud Director provider interface, go to Administration >> Settings >> General >> Timeouts.

    Click Edit.

    Enter 15 on the \"Idle session timeout\" line then click Save.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000295-AS-000263'
  tag gid: 'V-CDAP-10-000070'
  tag rid: 'SV-CDAP-10-000070'
  tag stig_id: 'CDAP-10-000070'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']

  result = http("https://#{input('vcdURL')}/api/admin/extension/settings/general",
                method: 'GET',
                headers: {
                  'accept' => "#{input('legacyApiVersion')}",
                  'Authorization' => "#{input('bearerToken')}"
                },
                ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    describe json(content: result.body) do
      its(['sessionTimeoutMinutes']) { should cmp '15' }
    end
  end
end
