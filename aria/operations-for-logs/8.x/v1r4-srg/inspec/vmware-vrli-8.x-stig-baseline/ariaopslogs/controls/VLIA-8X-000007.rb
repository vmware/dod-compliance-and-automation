control 'VLIA-8X-000007' do
  title 'VMware Aria Operations for Logs must terminate user sessions after a period of inactivity.'
  desc  "
    Automatic session termination addresses the termination of user-initiated logical sessions in contrast to the termination of network connections that are associated with communications sessions (i.e., network disconnect). A logical session (for local, network, and remote access) is initiated whenever a user (or process acting on behalf of a user) accesses an organizational information system. Such user sessions can be terminated (and thus terminate user access) without terminating network sessions.

    Session termination terminates all processes associated with a user's logical session except those processes that are specifically created by the user (i.e., session owner) to continue after the session is terminated.

    Conditions or trigger events requiring automatic session termination can include, for example, organization-defined periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use.

    This capability is typically reserved for specific application system functionality where the system owner, data owner, or organization requires additional assurance. Based upon requirements and events specified by the data or application owner, the application developer must incorporate logic into the application that will provide a control mechanism that disconnects users upon the defined event trigger. The methods for incorporating this requirement will be determined and specified on a case by case basis during the application design and development stages.
  "
  desc  'rationale', ''
  desc  'check', "
    Login to VMware Aria Operations for Logs as an administrator.

    In the slide-out menu on the left, choose Configuration >> General.

    In the \"BROWSER SESSION\" section, if the \"Session Timeout\" is not set to 30 minutes, this is a finding.
  "
  desc 'fix', "
    Login to VMware Aria Operations for Logs as an administrator.

    In the slide-out menu on the left, choose Configuration >> General.

    In the \"BROWSER SESSION\" section set the \"Session Timeout\" value to 30 and click Save.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000295-AU-000190'
  tag satisfies: ['SRG-APP-000389-AU-000180']
  tag gid: 'V-VLIA-8X-000007'
  tag rid: 'SV-VLIA-8X-000007'
  tag stig_id: 'VLIA-8X-000007'
  tag cci: ['CCI-002038', 'CCI-002361']
  tag nist: ['AC-12', 'IA-11']

  token = http("https://#{input('apipath')}/sessions",
               method: 'POST',
               headers: {
                 'Content-Type' => 'application/json',
                 'Accept' => 'application/json'
               },
               data: "{\"username\":\"#{input('username')}\",\"password\":\"#{input('password')}\",\"provider\":\"Local\"}",
               ssl_verify: false)

  describe token do
    its('status') { should cmp 200 }
  end

  unless token.status != 200
    sessID = JSON.parse(token.body)['sessionId']

    response = http("https://#{input('apipath')}/ui/browser-session",
                    method: 'GET',
                    headers: {
                      'Content-Type' => 'application/json',
                      'Accept' => 'application/json',
                      'Authorization' => "Bearer #{sessID}"
                    },
                    ssl_verify: false)

    describe response do
      its('status') { should cmp 200 }
    end

    unless response.status != 200
      describe json(content: response.body) do
        its(['timeout']) { should cmp 30 }
      end
    end
  end
end
