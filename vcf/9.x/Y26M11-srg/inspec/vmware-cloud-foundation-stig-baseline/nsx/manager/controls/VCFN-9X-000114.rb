control 'VCFN-9X-000114' do
  title 'The VMware Cloud Foundation NSX Manager must enable the global FIPS compliance mode for load balancers.'
  desc  'If unsecured protocols (lacking cryptographic mechanisms) are used for load balancing, the contents of those sessions will be susceptible to eavesdropping, potentially putting sensitive data at risk of compromise.'
  desc  'rationale', ''
  desc  'check', "
    From the NSX Manager web interface, go to the Home >> Monitoring Dashboards >> Compliance Report.

    Review the compliance report for code 72024 with description Load balancer FIPS global setting disabled.

    Note: This may also be checked via the API call GET https://<nsx-mgr>/policy/api/v1/infra/global-config

    If the global FIPS setting is disabled for load balancers, this is a finding.
  "
  desc 'fix', "
    Execute the following API call using curl or another REST API client:

    PUT https://<nsx-mgr>/policy/api/v1/infra/global-config

    Example request body:

    {
    \"fips\": {
    \"lb_fips_enabled\": true
    },
    \"resource_type\": \"GlobalConfig\",
    \"_revision\": 2
    }

    The global setting is used when the new load balancer instances are created. Changing the setting does not affect existing load balancer instances.

    To update existing load balancers to use this setting, do the following:

    From the NSX Manager web interface, go to the Networking >> Load Balancing and then click \"Edit\" on the target load balancer.

    In the attachment field, click the \"X\" to detach the load balancer from its current Gateway and click \"Save\".

    Edit the target load balancer again, reattach it to its Gateway, and then click \"Save\".

    Caution: Detaching a load balancer from the tier-1 gateway results in a traffic interruption for the load balancer instance.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag gid: 'V-VCFN-9X-000114'
  tag rid: 'SV-VCFN-9X-000114'
  tag stig_id: 'VCFN-9X-000114'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  result = http("https://#{input('nsx_managerAddress')}/policy/api/v1/infra/global-config",
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
      its(['fips', 'lb_fips_enabled']) { should cmp 'true' }
    end
  end
end
