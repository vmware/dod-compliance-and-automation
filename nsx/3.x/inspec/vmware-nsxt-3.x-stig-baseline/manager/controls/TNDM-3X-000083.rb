control 'TNDM-3X-000083' do
  title 'The NSX-T Manager must generate audit records when successful/unsuccessful attempts to delete administrator privileges occur.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the network device (e.g., module or policy filter).'
  desc 'check', 'From an NSX-T Manager shell, run the following command(s):

> get service async_replicator | find Logging
> get service http | find Logging
> get service manager | find Logging
> get service policy | find Logging

Expected result:
Logging level:     info

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'From an NSX-T Manager shell, run the following command(s):

> set service async_replicator logging-level info
> set service http logging-level info
> set service manager logging-level info
> set service policy logging-level info'
  impact 0.5
  tag check_id: 'C-55246r810359_chk'
  tag severity: 'medium'
  tag gid: 'V-251786'
  tag rid: 'SV-251786r879870_rule'
  tag stig_id: 'TNDM-3X-000083'
  tag gtitle: 'SRG-APP-000499-NDM-000319'
  tag fix_id: 'F-55200r810360_fix'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  result = http("https://#{input('nsxManager')}/api/v1/node/services/async_replicator",
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
      its(['service_properties', 'logging_level']) { should cmp 'INFO' }
    end
  end

  result = http("https://#{input('nsxManager')}/api/v1/node/services/http",
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
      its(['service_properties', 'logging_level']) { should cmp 'INFO' }
    end
  end

  result = http("https://#{input('nsxManager')}/api/v1/node/services/manager",
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
      its(['service_properties', 'logging_level']) { should cmp 'INFO' }
    end
  end

  result = http("https://#{input('nsxManager')}/api/v1/node/services/policy",
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
      its(['service_properties', 'logging_level']) { should cmp 'INFO' }
    end
  end
end
