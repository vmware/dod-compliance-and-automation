control 'NT0R-4X-000013' do
  title 'The NSX Tier-0 Gateway router must be configured to disable Protocol Independent Multicast (PIM) on all interfaces that are not required to support multicast routing.'
  desc %q(If multicast traffic is forwarded beyond the intended boundary, it could be intercepted by unauthorized or unintended personnel. Limiting where within the network a given multicast group's data is permitted to flow is an important first step in improving multicast security.

A scope zone is an instance of a connected region of a given scope. Zones of the same scope cannot overlap while zones of a smaller scope will fit completely within a zone of a larger scope. For example, Admin-local scope is smaller than Site-local scope, so the administratively configured boundary fits within the bounds of a site. According to RFC 4007 IPv6 Scoped Address Architecture (section 5), scope zones are also required to be "convex from a routing perspective"; that is, packets routed within a zone must not pass through any links that are outside of the zone. This requirement forces each zone to be one contiguous island rather than a series of separate islands.

As stated in the DOD IPv6 IA Guidance for MO3, "One should be able to identify all interfaces of a zone by drawing a closed loop on their network diagram, engulfing some routers and passing through some routers to include only some of their interfaces." Therefore, it is imperative that the network engineers have documented their multicast topology and thereby knows which interfaces are enabled for multicast. Once this is done, the zones can be scoped as required.)
  desc 'check', 'From the NSX Manager web interface, go to Networking >> Connectivity >> Tier-0 Gateways.

For every Tier-0 Gateway, expand the Tier-0 Gateway >> Interfaces and GRE Tunnels, and click on the number of interfaces present to open the interfaces dialog.

Expand each interface that is not required to support multicast routing, then expand "Multicast" and verify PIM is disabled.

If PIM is enabled on any interfaces that are not supporting multicast routing, this is a finding.'
  desc 'fix', 'Disable multicast PIM routing on interfaces that are not required to support multicast by doing the following:

From the NSX Manager web interface, go to Networking >> Connectivity >> Tier-0 Gateways and expand the target Tier-0 gateway.

Expand "Interfaces and GRE Tunnels", click on the number of interfaces present to open the interfaces dialog, and then select "Edit" on the target interface.

Expand "Multicast", change PIM to "disabled", and then click "Save".'
  impact 0.7
  ref 'DPMS Target VMware NSX 4.x Tier-0 Gateway Router'
  tag check_id: 'C-69307r994518_chk'
  tag severity: 'high'
  tag gid: 'V-265390'
  tag rid: 'SV-265390r994520_rule'
  tag stig_id: 'NT0R-4X-000013'
  tag gtitle: 'SRG-NET-000019-RTR-000003'
  tag fix_id: 'F-69215r994519_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']

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
          # See if multicast is enabled on the T0 itself
          t0mc = http("https://#{input('nsxManager')}/policy/api/v1/infra/tier-0s/#{t0id}/locale-services/#{t0lsid}/multicast",
                      method: 'GET',
                      headers: {
                        'Accept' => 'application/json',
                        'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                        'Cookie' => "#{input('sessionCookieId')}"
                      },
                      ssl_verify: false)

          # Get all T0 interfaces
          t0ints = http("https://#{input('nsxManager')}/policy/api/v1/infra/tier-0s/#{t0id}/locale-services/#{t0lsid}/interfaces",
                        method: 'GET',
                        headers: {
                          'Accept' => 'application/json',
                          'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                          'Cookie' => "#{input('sessionCookieId')}"
                        },
                        ssl_verify: false)

          describe t0ints do
            its('status') { should cmp 200 }
          end
          next unless t0ints.status == 200
          t0intsjson = JSON.parse(t0ints.body)
          t0mcjson = JSON.parse(t0mc.body)

          # 200 is returned if successfull and multicast has ever been enabled on the T0 otherwise we get a 404 and can assume disabled
          if t0mc.status == 200
            # If multicast is enabled on the T0 it should be in the list so we can determine if any interfaces should have it enabled
            if t0mcjson['enabled']
              describe t0id do
                it { should be_in input('t0multicastlist') }
              end
              describe t0mcjson['enabled'] do
                it { should cmp 'true' }
              end
              t0intsjson['results'].each do |int|
                # If the multicast property doesn't exist on the interface it's never been configured and is off and we can skip it
                next unless !int['multicast'].nil?
                # If the property exists and is true let's verify it against the list
                if int['multicast']['enabled'] == true
                  describe int do
                    its(['multicast', 'enabled']) { should cmp 'true' }
                    its(['id']) { should be_in input('t0mcinterfacelist') }
                  end
                # If it's not enabled then it should be false
                else
                  describe int do
                    its(['multicast', 'enabled']) { should cmp 'false' }
                  end
                end
              end
            # If multicast is not enabled on the T0 then no interfaces should have it enabled
            else
              describe t0mcjson['enabled'] do
                it { should cmp 'false' }
              end
              t0intsjson['results'].each do |int|
                if int['multicast'].nil?
                  describe json(content: int.to_json) do
                    its('multicast') { should be nil }
                  end
                else
                  describe int do
                    its(['multicast', 'enabled']) { should cmp 'false' }
                  end
                end
              end
            end
          # If 404 is returned then multicast has never been abled on the T0 and all interfaces should not have it enabled
          else
            t0intsjson['results'].each do |int|
              if int['multicast'].nil?
                describe json(content: int.to_json) do
                  its('multicast') { should be nil }
                end
              else
                describe int do
                  its(['multicast', 'enabled']) { should cmp 'false' }
                end
              end
            end
          end
        end
      end
    end
  end
end
