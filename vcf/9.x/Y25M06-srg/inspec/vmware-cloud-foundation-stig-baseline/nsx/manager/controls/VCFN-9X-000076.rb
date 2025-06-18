control 'VCFN-9X-000076' do
  title 'The VMware Cloud Foundation NSX Manager must be configured to protect against known types of denial-of-service (DoS) attacks by employing organization-defined security safeguards.'
  desc  "
    DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

    This requirement addresses the configuration of network devices to mitigate the impact of DoS attacks that have occurred or are ongoing on device availability. For each network device, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exist to limit, or in some cases eliminate, the effects of DoS attacks (e.g., limiting processes or restricting the number of sessions the device opens at one time). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks.

    The security safeguards cannot be defined at the DoD level because they vary according to the capabilities of the individual network devices and the security controls applied on the adjacent networks (for example, firewalls performing packet filtering to block DoS attacks).
  "
  desc  'rationale', ''
  desc  'check', "
    From an NSX Manager shell, run the following NSX CLI command:

    > get service http | find limit

    Example result:

    Client API rate limit: 100 requests/sec
    Client API concurrency limit: 40 connections
    Global API concurrency limit: 199 connections

    If the API limits are not configured as shown in the example result, this is a finding.
  "
  desc 'fix', "
    From an NSX Manager shell, run the following NSX CLI commands:

    > set service http client-api-rate-limit 100
    > set service http client-api-concurrency-limit 40
    > set service http global-api-concurrency-limit 199
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000435-NDM-000315'
  tag satisfies: ['SRG-APP-000001-NDM-000200']
  tag gid: 'V-VCFN-9X-000076'
  tag rid: 'SV-VCFN-9X-000076'
  tag stig_id: 'VCFN-9X-000076'
  tag cci: ['CCI-000054', 'CCI-002385']
  tag nist: ['AC-10', 'SC-5 a']

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
      its('client_api_concurrency_limit') { should cmp '40' }
      its('client_api_rate_limit') { should cmp '100' }
      its('global_api_concurrency_limit') { should cmp '199' }
    end
  end
end
