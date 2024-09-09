control 'NT0R-4X-000106' do
  title 'The NSX Tier-0 Gateway router must be configured to have routing protocols disabled if not in use.'
  desc 'A compromised router introduces risk to the entire network infrastructure, as well as data resources that are accessible via the network. The perimeter defense has no oversight or control of attacks by malicious users within the network. Preventing network breaches from within is dependent on implementing a comprehensive defense-in-depth strategy, including securing each device connected to the network. This is accomplished by following and implementing all security guidance applicable for each node type. A fundamental step in securing each router is to enable only the capabilities required for operation.'
  desc 'check', 'From the NSX Manager web interface, go to Networking >> Connectivity >> Tier-0 Gateways.

For every Tier-0 Gateway, expand the Tier-0 Gateway to view if border gateway protocol (BGP) or Open Shortest Path First (OSPF) is enabled.

If BGP and/or OSPF is enabled and not in use, this is a finding.'
  desc 'fix', 'If not used in the implementation, then disable BGP, do the following:

From the NSX Manager web interface, go to Networking >> Connectivity >> Tier-0 Gateways and edit the target Tier-0 Gateway.

Expand BGP, change from "On" to "Off", and then click "Save".

If not used in the implementation, then disable OSPF, do the following:

From the NSX Manager web interface, go to Networking >> Connectivity >> Tier-0 Gateways and edit the target Tier-0 Gateway.

Expand OSPF, change from "Enabled" to "Disabled", and then click "Save".'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000131-RTR-000035'
  tag gid: 'V-263311'
  tag rid: 'SV-263311r977700_rule'
  tag stig_id: 'NT0R-4X-000106'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  t0s = http("https://#{input('nsxManager')}/policy/api/v1/infra/tier-0s",
             method: 'GET',
             headers: {
               'Accept' => 'application/json',
               'X-XSRF-TOKEN' => "#{input('sessionToken')}",
               'Cookie' => "#{input('sessionCookieId')}"
             },
             ssl_verify: false)

  describe t0s do
    its('status') { should cmp 200 }
  end
  unless t0s.status != 200
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
          # Check for BGP enabled
          bgp = http("https://#{input('nsxManager')}/policy/api/v1/infra/tier-0s/#{t0id}/locale-services/#{t0lsid}/bgp",
                     method: 'GET',
                     headers: {
                       'Accept' => 'application/json',
                       'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                       'Cookie' => "#{input('sessionCookieId')}"
                     },
                     ssl_verify: false)

          describe bgp do
            its('status') { should cmp 200 }
          end
          next unless bgp.status == 200
          bgpjson = JSON.parse(bgp.body)
          if bgpjson['enabled']
            bgpnbrs = http("https://#{input('nsxManager')}/policy/api/v1/infra/tier-0s/#{t0id}/locale-services/#{t0lsid}/bgp/neighbors",
                           method: 'GET',
                           headers: {
                             'Accept' => 'application/json',
                             'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                             'Cookie' => "#{input('sessionCookieId')}"
                           },
                           ssl_verify: false)

            describe bgpnbrs do
              its('status') { should cmp 200 }
            end
            next unless bgpnbrs.status == 200
            bgpnbrsjson = JSON.parse(bgpnbrs.body)
            describe bgpnbrsjson['result_count'] do
              it { should cmp > 0 }
            end
          else
            describe "BGP not enabled on T0: #{t0['display_name']}" do
              subject { bgpjson['enabled'] }
              it { should cmp 'false' }
            end
          end

          # Check for OSPF
          # vrfs do not have OSPF configuration
          next unless t0['vrf_config'].nil?
          ospf = http("https://#{input('nsxManager')}/policy/api/v1/infra/tier-0s/#{t0id}/locale-services/#{t0lsid}/ospf",
                      method: 'GET',
                      headers: {
                        'Accept' => 'application/json',
                        'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                        'Cookie' => "#{input('sessionCookieId')}"
                      },
                      ssl_verify: false)

          describe ospf do
            its('status') { should cmp 200 }
          end
          next unless ospf.status == 200
          ospfjson = JSON.parse(ospf.body)
          if ospfjson['enabled']
            ospfareas = http("https://#{input('nsxManager')}/policy/api/v1/infra/tier-0s/#{t0id}/locale-services/#{t0lsid}/ospf/areas",
                             method: 'GET',
                             headers: {
                               'Accept' => 'application/json',
                               'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                               'Cookie' => "#{input('sessionCookieId')}"
                             },
                             ssl_verify: false)

            describe ospfareas do
              its('status') { should cmp 200 }
            end
            next unless ospfareas.status == 200
            ospfareasjson = JSON.parse(ospfareas.body)
            describe ospfareasjson['result_count'] do
              it { should cmp > 0 }
            end
          else
            describe "OSPF not enabled on T0: #{t0['display_name']}" do
              subject { ospfjson['enabled'] }
              it { should cmp 'false' }
            end
          end
        end
      end
    end
  end
end
