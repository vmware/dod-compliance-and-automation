control 'VCFR-9X-000067' do
  title 'The VMware Cloud Foundation NSX Tier-0 Gateway must be configured to use the BGP maximum prefixes feature to protect against route table flooding and prefix de-aggregation attacks.'
  desc  "
    The effects of prefix de-aggregation can degrade router performance due to the size of routing tables and also result in black-holing legitimate traffic. Initiated by an attacker or a misconfigured router, prefix de-aggregation occurs when the announcement of a large prefix is fragmented into a collection of smaller prefix announcements.

    In 1997, misconfigured routers in the Florida Internet Exchange network (AS7007) de-aggregated every prefix in their routing table and started advertising the first /24 block of each of these prefixes as their own. Faced with this additional burden, the internal routers became overloaded and crashed repeatedly. This caused prefixes advertised by these routers to disappear from routing tables and reappear when the routers came back online. As the routers came back after crashing, they were flooded with the routing table information by their neighbors. The flood of information would again overwhelm the routers and cause them to crash. This process of route flapping served to destabilize not only the surrounding network but also the entire Internet. Routers trying to reach those addresses would choose the smaller, more specific /24 blocks first. This caused backbone networks throughout North America and Europe to crash.

    Maximum prefix limits on peer connections combined with aggressive prefix-size filtering of customers' reachability advertisements will effectively mitigate the de-aggregation risk. BGP maximum prefix must be used on all eBGP routers to limit the number of prefixes that it should receive from a particular neighbor, whether customer or peering AS. Consider each neighbor and how many routes they should be advertising and set a threshold slightly higher than the number expected.
  "
  desc  'rationale', ''
  desc  'check', "
    If the Tier-0 Gateway is not using BGP, this is Not Applicable.

    From the NSX Manager web interface, go to Networking >> Connectivity >> Tier-0 Gateways.

    For every Tier-0 Gateway with BGP enabled, expand the Tier-0 Gateway.

    Expand BGP, click on the number next to BGP Neighbors, and then view the Router Filters for each neighbor.

    If Maximum Routes is not configured or a route filter does not exist for each BGP neighbor, this is a finding.
  "
  desc 'fix', "
    To set maximum prefixes for BGP neighbors do the following:

    From the NSX Manager web interface, go to Networking >> Connectivity >> Tier-0 Gateways and expand the target Tier-0 gateway.

    Expand BGP. Next to BGP Neighbors, click on the number present to open the dialog, and then select \"Edit\" on the target BGP Neighbor.

    Click \"Router Filter\", add or edit an existing router filter, enter a number for Maximum Routes, and then click \"Add\".

    Click \"Apply\", then click \"Save\" to finish the configuration.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000362-RTR-000117'
  tag gid: 'V-VCFR-9X-000067'
  tag rid: 'SV-VCFR-9X-000067'
  tag stig_id: 'VCFR-9X-000067'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']

  t0s = http("https://#{input('nsx_managerAddress')}/policy/api/v1/infra/tier-0s",
             method: 'GET',
             headers: {
               'Accept' => 'application/json',
               'X-XSRF-TOKEN' => "#{input('nsx_sessionToken')}",
               'Cookie' => "#{input('nsx_sessionCookieId')}"
             },
             ssl_verify: false)

  describe t0s do
    its('status') { should cmp 200 }
  end
  unless t0s.status != 200
    t0sjson = JSON.parse(t0s.body)
    if t0sjson['result_count'] == 0
      impact 0.0
      describe 'No T0 Gateways are deployed. This is Not Applicable.' do
        skip 'No T0 Gateways are deployed. This is Not Applicable.'
      end
    else
      t0sjson['results'].each do |t0|
        t0id = t0['id']
        # Get locale-services id for T0
        t0lss = http("https://#{input('nsx_managerAddress')}/policy/api/v1/infra/tier-0s/#{t0id}/locale-services",
                     method: 'GET',
                     headers: {
                       'Accept' => 'application/json',
                       'X-XSRF-TOKEN' => "#{input('nsx_sessionToken')}",
                       'Cookie' => "#{input('nsx_sessionCookieId')}"
                     },
                     ssl_verify: false)

        t0lssjson = JSON.parse(t0lss.body)
        next unless t0lssjson['result_count'] != 0
        t0lssjson['results'].each do |t0ls|
          t0lsid = t0ls['id']
          bgp = http("https://#{input('nsx_managerAddress')}/policy/api/v1/infra/tier-0s/#{t0id}/locale-services/#{t0lsid}/bgp",
                     method: 'GET',
                     headers: {
                       'Accept' => 'application/json',
                       'X-XSRF-TOKEN' => "#{input('nsx_sessionToken')}",
                       'Cookie' => "#{input('nsx_sessionCookieId')}"
                     },
                     ssl_verify: false)

          describe bgp do
            its('status') { should cmp 200 }
          end
          next unless bgp.status == 200
          bgpjson = JSON.parse(bgp.body)
          if bgpjson['enabled']
            bgpnbrs = http("https://#{input('nsx_managerAddress')}/policy/api/v1/infra/tier-0s/#{t0id}/locale-services/#{t0lsid}/bgp/neighbors",
                           method: 'GET',
                           headers: {
                             'Accept' => 'application/json',
                             'X-XSRF-TOKEN' => "#{input('nsx_sessionToken')}",
                             'Cookie' => "#{input('nsx_sessionCookieId')}"
                           },
                           ssl_verify: false)

            describe bgpnbrs do
              its('status') { should cmp 200 }
            end
            next unless bgpnbrs.status == 200
            bgpnbrsjson = JSON.parse(bgpnbrs.body)
            if bgpnbrsjson['result_count'] != 0
              bgpnbrsjson['results'].each do |bgpnbr|
                if !bgpnbr['route_filtering'].nil?
                  bgpnbr['route_filtering'].each do |rf|
                    describe "T0 Gateway: #{t0['display_name']}. BGP Neighbor" do
                      subject { rf }
                      its(['maximum_routes']) { should_not be nil }
                    end
                  end
                else
                  describe "T0 Gateway: #{t0['display_name']}. BGP Neighbor" do
                    subject { bgpnbr }
                    its(['route_filtering']) { should_not be nil }
                  end
                end
              end
            else
              describe "No BGP Neighbors found on T0 Gateway: #{t0['display_name']}. BGP Neighbors" do
                subject { bgpnbrsjson }
                its(['result_count']) { should cmp 0 }
              end
            end
          else
            describe "T0 Gateway: #{t0['display_name']} BGP" do
              subject { bgpjson }
              its(['enabled']) { should cmp 'false' }
            end
          end
        end
      end
    end
  end
end
