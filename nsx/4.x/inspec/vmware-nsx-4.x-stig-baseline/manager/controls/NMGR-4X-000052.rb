control 'NMGR-4X-000052' do
  title 'The NSX Manager must terminate all network connections associated with a session after 10 minutes of inactivity.'
  desc  "
    Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element.

    Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, or de-allocating networking assignments at the application level if multiple application sessions are using a single, operating system-level network connection. This does not mean that the device terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.
  "
  desc  'rationale', ''
  desc  'check', "
    From an NSX Manager shell, run the following command:

    > get service http | find Session

    Expected result:
    Session timeout: 600

    If the session timeout is not configured to 600 or less, this is a finding.

    From an NSX Manager shell, run the following command:

    > get cli-timeout

    Expected result:
    600 seconds

    If the CLI timeout is not configured to 600 or less, this is a finding.
  "
  desc 'fix', "
    From an NSX-T Manager shell, run the following commands:

    > set service http session-timeout 600
    > set cli-timeout 600
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000190-NDM-000267'
  tag satisfies: ['SRG-APP-000186-NDM-000266', 'SRG-APP-000400-NDM-000313']
  tag gid: 'V-NMGR-4X-000052'
  tag rid: 'SV-NMGR-4X-000052'
  tag stig_id: 'NMGR-4X-000052'
  tag cci: ['CCI-000879', 'CCI-001133', 'CCI-002007']
  tag nist: ['IA-5 (13)', 'MA-4 e', 'SC-10']

  result = http("https://#{input('nsxManager')}/api/v1/cluster/api-service",
                method: 'GET',
                headers: {
                  'Accept' => 'application/json',
                  'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                  'Cookie' => "#{input('sessionCookieId')}",
                  },
                ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    describe json(content: result.body) do
      its('session_timeout') { should cmp <= '600' }
    end
  end

  result = http("https://#{input('nsxManager')}/api/v1/node",
                method: 'GET',
                headers: {
                  'Accept' => 'application/json',
                  'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                  'Cookie' => "#{input('sessionCookieId')}",
                  },
                ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    describe json(content: result.body) do
      its('cli_timeout') { should cmp <= '600' }
    end
  end
end
