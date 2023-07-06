control 'T0RT-3X-000003' do
  title 'The NSX-T Tier-0 Gateway must be configured to reject inbound route advertisements for any prefixes belonging to the local autonomous system (AS).'
  desc  'Accepting route advertisements belonging to the local AS can result in traffic looping or being black holed, or at a minimum using a non-optimized path.'
  desc  'rationale', ''
  desc  'check', "
    If the Tier-0 Gateway is not using eBGP, this is Not Applicable.

    From the NSX-T Manager web interface, go to Networking >> Tier-0 Gateways.

    For every Tier-0 Gateway, expand Tier-0 Gateway >>BGP. Near to BGP Neighbors, click on the number present to open the dialog.

    For each neighbor examine any router filters to determine if any inbound route filters are applied.

    If the In Filter is not configured with a prefix list that rejects prefixes belonging to the local AS, this is a finding.
  "
  desc 'fix', "
    To configure a route filter do the following:

    From the NSX-T Manager web interface, go to Networking >> Tier-0 Gateways >> edit the target Tier-0 gateway.

    Expand Routing and open the IP Prefix List dialog. Edit an existing, or add a new prefix list that contains the prefixes belonging to the local AS to deny them. Click \"Save\".

    To apply a route filter to a BGP neighbor do the following:

    From the NSX-T Manager web interface, go to Networking >> Tier-0 Gateways and edit the target Tier-0 gateway.

    Expand BGP, and next to BGP Neighbors, click on the number present to open the dialog. Select \"Edit\" on the target BGP Neighbor.

    Open the router filter dialog and add or edit an existing router filter. Configure the In Filter with the filter previously created and click \"Save\", \"Add\", \"Apply\", and \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000018-RTR-000003'
  tag gid: 'V-251744'
  tag rid: 'SV-251744r810116_rule'
  tag stig_id: 'T0RT-3X-000003'
  tag fix_id: 'F-55135r810115_fix'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']

  t0s = http("https://#{input('nsxManager')}/policy/api/v1/infra/tier-0s",
              method: 'GET',
              headers: {
                'Accept' => 'application/json',
                'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                'Cookie' => "#{input('sessionCookieId')}",
                },
              ssl_verify: false)

  describe t0s do
    its('status') { should cmp 200 }
  end
  unless t0s.status != 200
    t0sjson = JSON.parse(t0s.body)
    if t0sjson['results'] == []
      describe 'No T0 Gateways are deployed...skipping...' do
        skip 'No T0 Gateways are deployed...skipping...'
      end
    else
      t0sjson['results'].each do |t0|
        t0id = t0['id']
        bgp = http("https://#{input('nsxManager')}/policy/api/v1/infra/tier-0s/#{t0id}/locale-services/default/bgp",
                  method: 'GET',
                  headers: {
                    'Accept' => 'application/json',
                    'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                    'Cookie' => "#{input('sessionCookieId')}",
                    },
                  ssl_verify: false)

        describe bgp do
          its('status') { should cmp 200 }
        end
        next unless bgp.status == 200
        bgpjson = JSON.parse(bgp.body)
        if bgpjson['enabled']
          describe "Detected T0: #{t0['display_name']} with BGP enabled...manually verify router filters and prefixes are configured on neighbors to reject addresses from the local AS" do
            skip "Detected T0: #{t0['display_name']} with BGP enabled...manually verify router filters and prefixes are configured on neighbors to reject addresses from the local AS"
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
