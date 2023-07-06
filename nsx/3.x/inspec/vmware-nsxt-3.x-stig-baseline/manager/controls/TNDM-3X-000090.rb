control 'TNDM-3X-000090' do
  title 'The NSX-T Manager must generate log records for the info level to capture the DoD-required auditable events.'
  desc  'Auditing and logging are key components of any security architecture. Logging the actions of specific events provides a means to investigate an attack; to recognize resource utilization or capacity thresholds; or to identify an improperly configured network device. If auditing is not comprehensive, it will not be useful for intrusion monitoring, security investigations, and forensic analysis.'
  desc  'rationale', ''
  desc  'check', "
    From an NSX-T Manager shell, run the following command(s):

    > get service async_replicator | find Logging
    > get service http | find Logging
    > get service manager | find Logging
    > get service policy | find Logging

    Expected result:
    Logging level: info

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    From an NSX-T Manager shell, run the following command(s):

    > set service async_replicator logging-level info
    > set service http logging-level info
    > set service manager logging-level info
    > set service policy logging-level info
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-NDM-000334'
  tag gid: 'V-251788'
  tag rid: 'SV-251788r810367_rule'
  tag stig_id: 'TNDM-3X-000090'
  tag fix_id: 'F-55202r810366_fix'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']

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
