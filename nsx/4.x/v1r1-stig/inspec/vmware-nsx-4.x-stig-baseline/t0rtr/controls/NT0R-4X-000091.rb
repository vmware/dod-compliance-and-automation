control 'NT0R-4X-000091' do
  title 'The NSX Tier-0 Gateway router must be configured to use its loopback address as the source address for Internal Border Gateway Protocol (IBGP) peering sessions.'
  desc 'Using a loopback address as the source address offers a multitude of uses for security, access, management, and scalability of the Border Gateway Protocol (BGP) routers. It is easier to construct appropriate ingress filters for router management plane traffic destined to the network management subnet since the source addresses will be from the range used for loopback interfaces instead of a larger range of addresses used for physical interfaces. Log information recorded by authentication and syslog servers will record the router’s loopback address instead of the numerous physical interface addresses.

The routers within the iBGP domain should also use loopback addresses as the source address when establishing BGP sessions.'
  desc 'check', '
    If the Tier-0 Gateway is not using iBGP, this is Not Applicable.

    From the NSX Manager web interface, go to Networking >> Connectivity >> Tier-0 Gateways.

    For every Tier-0 Gateway with BGP enabled, expand the Tier-0 Gateway.

    Expand BGP, click on the number next to BGP Neighbors, then view the source address for each neighbor.

    If the Source Address is not configured as the Tier-0 Gateway loopback address for the iBGP session, this is a finding.
  '
  desc 'fix', 'To configure a loopback interface, do the following:

From the NSX Manager web interface, go to Networking >> Connectivity >> Tier-0 Gateways and expand the target Tier-0 gateway.

Expand interfaces and click "Add Interface".

Enter a name, select "Loopback" as the Type, enter an IP address, select an Edge Node for the interface, then click "Save".

Note: More than one loopback may need to be configured depending on the routing architecture.


To set the source address for BGP neighbors, do the following:

From the NSX Manager web interface, go to Networking >> Connectivity >> Tier-0 Gateways >> expand the target Tier-0 gateway.

Expand BGP >> next to BGP Neighbors, click on the number present to open the dialog >> select "Edit" on the target BGP Neighbor.

Under Source Addresses, configure the source address with the loopback address and click "Save".'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000512-RTR-000001'
  tag gid: 'V-263309'
  tag rid: 'SV-263309r977694_rule'
  tag stig_id: 'NT0R-4X-000091'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  t0s = http("https://#{input('nsxManager')}/policy/api/v1/infra/tier-0s",
             method: 'GET',
             headers: {
               'Accept' => 'application/json',
               'X-XSRF-TOKEN' => "#{input('sessionToken')}",
               'Cookie' => "#{input('sessionCookieId')}"
             },
             ssl_verify: false)

  # if status is not 200 return a failure but if it's 200 do not run the test so this control does not pass and is properly skipped as a manual review.
  if t0s.status != 200
    describe t0s do
      its('status') { should cmp 200 }
    end
  else
    t0sjson = JSON.parse(t0s.body)
    if t0sjson['results'] == []
      impact 0.0
      describe 'No T0 Gateways are deployed. This is Not Applicable.' do
        skip 'No T0 Gateways are deployed. This is Not Applicable.'
      end
    else
      t0sjson['results'].each do |t0|
        t0id = t0['id']
        # Get locale-services id for T0
        t0lss = http("https://#{input('nsxManager')}/policy/api/v1/infra/tier-0s/#{t0id}/locale-services",
                     method: 'GET',
                     headers: {
                       'Accept' => 'application/json',
                       'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                       'Cookie' => "#{input('sessionCookieId')}"
                     },
                     ssl_verify: false)

        t0lssjson = JSON.parse(t0lss.body)
        next unless t0lssjson['result_count'] != 0
        t0lssjson['results'].each do |t0ls|
          t0lsid = t0ls['id']
          bgp = http("https://#{input('nsxManager')}/policy/api/v1/infra/tier-0s/#{t0id}/locale-services/#{t0lsid}/bgp",
                     method: 'GET',
                     headers: {
                       'Accept' => 'application/json',
                       'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                       'Cookie' => "#{input('sessionCookieId')}"
                     },
                     ssl_verify: false)

          next unless bgp.status == 200
          bgpjson = JSON.parse(bgp.body)
          if bgpjson['enabled']
            describe "Detected T0: #{t0['display_name']} with BGP enabled...manually verify the source address for each neighbor is a loopback address for iBGP sessions" do
              skip "Detected T0: #{t0['display_name']} with BGP enabled...manually verify the source address for each neighbor is a loopback address for iBGP sessions"
            end
          else
            describe "BGP not enabled on T0: #{t0['display_name']}" do
              subject { bgpjson['enabled'] }
              it { should cmp 'false' }
            end
          end
        end
      end
    end
  end
end
