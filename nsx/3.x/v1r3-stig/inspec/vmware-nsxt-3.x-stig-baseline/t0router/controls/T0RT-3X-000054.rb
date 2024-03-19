control 'T0RT-3X-000054' do
  title 'The NSX-T Tier-0 Gateway must be configured to implement message authentication for all control plane protocols.'
  desc %q(A rogue router could send a fictitious routing update to convince a site's perimeter router to send traffic to an incorrect or even a rogue destination. This diverted traffic could be analyzed to learn confidential information about the site's network or used to disrupt the network's ability to communicate with other networks. This is known as a "traffic attraction attack" and is prevented by configuring neighbor router authentication for routing updates.)
  desc 'check', 'If the Tier-0 Gateway is not using BGP or OSPF, this is Not Applicable.

Since the NSX-T Tier-0 Gateway does not reveal if a BGP password is configured, interview the router administrator to determine if a password is configured on BGP neighbors.

If BGP neighbors do not have a password configured, this is a finding.

To verify OSPF areas are using authentication do the following:

From the NSX-T Manager web interface, go to Networking >> Tier-0 Gateways.

For every Tier-0 Gateway expand the "Tier-0 Gateway".

Expand "OSPF", click the number next to Area Definition, and view the Authentication field for each area.

If OSPF area definitions do not have Password or MD5 set for authentication, this is a finding.

Note: OSPF support was introduced in version 3.1.1.'
  desc 'fix', 'To set authentication for BGP neighbors do the following:

From the NSX-T Manager web interface, go to Networking >> Tier-0 Gateways, and expand the target Tier-0 gateway.

Expand BGP. Next to BGP Neighbors, click on the number present to open the dialog, then select "Edit" on the target BGP Neighbor.

Under Timers & Password, enter a password up to 20 characters, and then click "Save".

To set authentication for OSPF Area definitions do the following:

From the NSX-T Manager web interface, go to Networking >> Tier-0 Gateways, and expand the target Tier-0 gateway.

Expand OSPF. Next to Area Definition, click on the number present to open the dialog, and then select "Edit" on the target OSPF Area.

Change the Authentication drop-down to Password or MD5, enter a Key ID and/or Password, and then click "Save".'
  impact 0.5
  tag check_id: 'C-55188r810135_chk'
  tag severity: 'medium'
  tag gid: 'V-251751'
  tag rid: 'SV-251751r856692_rule'
  tag stig_id: 'T0RT-3X-000054'
  tag gtitle: 'SRG-NET-000230-RTR-000001'
  tag fix_id: 'F-55142r810136_fix'
  tag cci: ['CCI-000366', 'CCI-002205']
  tag nist: ['CM-6 b', 'AC-4 (17)']

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
      describe 'No T0 Gateways are deployed...skipping...' do
        skip 'No T0 Gateways are deployed...skipping...'
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
          # Check for BGP Neighbor passwords
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
            bgpnbrsjson['results'].each do |bgpnbr|
              describe bgpnbr do
                its(['password_set']) { should cmp 'true' }
              end
            end
          else
            describe "BGP not enabled on T0: #{t0['display_name']}" do
              subject { bgpjson['enabled'] }
              it { should cmp 'false' }
            end
          end

          # Check for OSPF authentication
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
            ospfareasjson['results'].each do |ospfarea|
              describe ospfarea do
                its(['authentication', 'mode']) { should be_in ['PASSWORD', 'MD5'] }
              end
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
