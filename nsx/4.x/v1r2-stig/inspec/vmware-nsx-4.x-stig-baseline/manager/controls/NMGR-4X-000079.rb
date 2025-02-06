control 'NMGR-4X-000079' do
  title 'The NSX Manager must be configured to protect against denial-of-service (DoS) attacks by limit the number of concurrent sessions to an organization-defined number.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

Limiting the number of concurrent open sessions helps limit the risk of DoS attacks.

Organizations may define the maximum number of concurrent sessions for system accounts globally or by connection type. By default, the NSX Manager has a protection mechanism in place to prevent the API from being overloaded. This setting also addresses concurrent sessions for integrations into NSX API to monitor or configure NSX.

'
  desc 'check', 'From an NSX Manager shell, run the following command:

> get service http | find limit

Expected result:
Client API concurrency limit: 40 connections
Global API concurrency limit: 199 connections

If the NSX does not limit the number of concurrent sessions to an organization-defined number, this is a finding.'
  desc 'fix', 'From an NSX Manager shell, run the following commands:

> set service http client-api-concurrency-limit 40
> set service http global-api-concurrency-limit 199

Note: The limit numbers in this example, while not mandatory, are the vendor recommend options. Setting the limits to lower numbers in a large environment that is very busy may cause operational issues. Setting the limits higher may cause resource contention so should be tested and monitored.'
  impact 0.5
  ref 'DPMS Target VMware NSX 4.x Manager NDM'
  tag check_id: 'C-69263r994259_chk'
  tag severity: 'medium'
  tag gid: 'V-265346'
  tag rid: 'SV-265346r994261_rule'
  tag stig_id: 'NMGR-4X-000079'
  tag gtitle: 'SRG-APP-000435-NDM-000315'
  tag fix_id: 'F-69171r994260_fix'
  tag satisfies: ['SRG-APP-000435-NDM-000315', 'SRG-APP-000001-NDM-000200']
  tag 'documentable'
  tag cci: ['CCI-002385', 'CCI-000054']
  tag nist: ['SC-5 a', 'AC-10']

  result = http("https://#{input('nsxManager')}/api/v1/cluster/api-service",
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
      its('client_api_concurrency_limit') { should cmp '40' }
      its('client_api_rate_limit') { should cmp '100' }
      its('global_api_concurrency_limit') { should cmp '199' }
    end
  end
end
