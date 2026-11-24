control 'VCFN-9X-000050' do
  title 'The VMware Cloud Foundation NSX Manager must terminate all network connections associated with a session after five minutes of inactivity.'
  desc  "
    Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element.

    Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, or de-allocating networking assignments at the application level if multiple application sessions are using a single, operating system-level network connection. This does not mean that the device terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.
  "
  desc  'rationale', ''
  desc  'check', "
    From an NSX Manager shell, run the following NSX CLI command:

    > get service http | find Session

    Example result:

    Session timeout: 300

    If the session timeout is configured to \"0\" or is greater than \"300\", this is a finding.

    From an NSX Manager shell, run the following NSX CLI command:

    > get cli-timeout

    Example result:

    300 seconds

    If the CLI timeout is configured to \"0\" or is greater than \"300\", this is a finding.
  "
  desc 'fix', "
    From an NSX Manager shell, run the following NSX CLI commands:

    > set service http session-timeout 300
    > set cli-timeout 300
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000190-NDM-000267'
  tag satisfies: ['SRG-APP-000400-NDM-000313']
  tag gid: 'V-VCFN-9X-000050'
  tag rid: 'SV-VCFN-9X-000050'
  tag stig_id: 'VCFN-9X-000050'
  tag cci: ['CCI-001133', 'CCI-002007']
  tag nist: ['IA-5 (13)', 'SC-10']

  result = http("https://#{input('nsx_managerAddress')}/api/v1/cluster/api-service",
                method: 'GET',
                headers: {
                  'Accept' => 'application/json',
                  'X-XSRF-TOKEN' => "#{input('nsx_sessionToken')}",
                  'Cookie' => "#{input('nsx_sessionCookieId')}"
                },
                ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    describe json(content: result.body) do
      its('session_timeout') { should cmp <= '300' }
      its('session_timeout') { should_not cmp '0' }
    end
  end

  result = http("https://#{input('nsx_managerAddress')}/api/v1/node",
                method: 'GET',
                headers: {
                  'Accept' => 'application/json',
                  'X-XSRF-TOKEN' => "#{input('nsx_sessionToken')}",
                  'Cookie' => "#{input('nsx_sessionCookieId')}"
                },
                ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    describe json(content: result.body) do
      its('cli_timeout') { should cmp <= '300' }
      its('cli_timeout') { should_not cmp '0' }
    end
  end
end
