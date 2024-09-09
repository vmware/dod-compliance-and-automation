control 'NMGR-4X-000007' do
  title 'The NSX Manager must configure logging levels for services to ensure audit records are generated.'
  desc '
    Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

    Audit records can be generated from various components within the network device (e.g., module or policy filter).
  '
  desc 'check', '
    From an NSX Manager shell, run the following commands:

    > get service async_replicator | find Logging
    > get service auth | find Logging
    > get service http | find Logging
    > get service manager | find Logging
    > get service telemetry | find Logging

    Expected result:
    Logging level: info

    If any service listed does not have logging level configured to "info", this is a finding.
  '
  desc 'fix', '
    From an NSX Manager shell, run the following commands:

    > set service async_replicator logging-level info
    > set service auth logging-level info
    > set service http logging-level info
    > set service manager logging-level info
    > set service telemetry logging-level info
  '
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000027-NDM-000209'
  tag satisfies: ['SRG-APP-000495-NDM-000318', 'SRG-APP-000499-NDM-000319', 'SRG-APP-000503-NDM-000320', 'SRG-APP-000504-NDM-000321', 'SRG-APP-000505-NDM-000322', 'SRG-APP-000506-NDM-000323', 'SRG-APP-000516-NDM-000334']
  tag gid: 'V-263202'
  tag rid: 'SV-263202r977373_rule'
  tag stig_id: 'NMGR-4X-000007'
  tag cci: ['CCI-000169', 'CCI-000172', 'CCI-001403']
  tag nist: ['AC-2 (4)', 'AU-12 a', 'AU-12 c']

  result = http("https://#{input('nsxManager')}/api/v1/node/services/async_replicator",
                method: 'GET',
                headers: {
                  'Accept' => 'application/json',
                  'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                  'Cookie' => "#{input('sessionCookieId')}"
                },
                ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    describe json(content: result.body) do
      its(['service_properties', 'logging_level']) { should cmp 'INFO' }
    end
  end

  result = http("https://#{input('nsxManager')}/api/v1/node/services/auth",
                method: 'GET',
                headers: {
                  'Accept' => 'application/json',
                  'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                  'Cookie' => "#{input('sessionCookieId')}"
                },
                ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    describe json(content: result.body) do
      its(['service_properties', 'logging_level']) { should cmp 'INFO' }
    end
  end

  result = http("https://#{input('nsxManager')}/api/v1/node/services/http",
                method: 'GET',
                headers: {
                  'Accept' => 'application/json',
                  'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                  'Cookie' => "#{input('sessionCookieId')}"
                },
                ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    describe json(content: result.body) do
      its(['service_properties', 'logging_level']) { should cmp 'INFO' }
    end
  end

  result = http("https://#{input('nsxManager')}/api/v1/node/services/manager",
                method: 'GET',
                headers: {
                  'Accept' => 'application/json',
                  'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                  'Cookie' => "#{input('sessionCookieId')}"
                },
                ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    describe json(content: result.body) do
      its(['service_properties', 'logging_level']) { should cmp 'INFO' }
    end
  end

  result = http("https://#{input('nsxManager')}/api/v1/node/services/telemetry",
                method: 'GET',
                headers: {
                  'Accept' => 'application/json',
                  'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                  'Cookie' => "#{input('sessionCookieId')}"
                },
                ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    describe json(content: result.body) do
      its(['service_properties', 'logging_level']) { should cmp 'INFO' }
    end
  end
end
