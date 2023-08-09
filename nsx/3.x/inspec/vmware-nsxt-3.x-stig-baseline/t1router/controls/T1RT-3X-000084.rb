control 'T1RT-3X-000084' do
  title 'The NSX-T Tier-1 Gateway must be configured to have multicast disabled if not in use.'
  desc 'A compromised router introduces risk to the entire network infrastructure, as well as data resources that are accessible via the network. The perimeter defense has no oversight or control of attacks by malicious users within the network. Preventing network breaches from within is dependent on implementing a comprehensive defense-in-depth strategy, including securing each device connected to the network. This is accomplished by following and implementing all security guidance applicable for each node type. A fundamental step in securing each router is to enable only the capabilities required for operation.'
  desc 'check', 'From the NSX-T Manager web interface, go to Networking >> Tier-1 Gateways.

For every Tier-1 Gateway, expand the Tier-1 Gateway then expand Multicast to view the Multicast configuration.

If Multicast is enabled and not in use, this is a finding.'
  desc 'fix', 'To disable Multicast do the following:

From the NSX-T Manager web interface, go to Networking >> Tier-1 Gateways and edit the target Tier-1 Gateway.

Expand Multicast and change from "Enabled" to "Disabled" and then click "Save".'
  impact 0.3
  tag check_id: 'C-55210r810217_chk'
  tag severity: 'low'
  tag gid: 'V-251773'
  tag rid: 'SV-251773r810219_rule'
  tag stig_id: 'T1RT-3X-000084'
  tag gtitle: 'SRG-NET-000131-RTR-000035'
  tag fix_id: 'F-55164r810218_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  t1s = http("https://#{input('nsxManager')}/policy/api/v1/infra/tier-1s",
              method: 'GET',
              headers: {
                'Accept' => 'application/json',
                'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                'Cookie' => "#{input('sessionCookieId')}",
                },
              ssl_verify: false)

  describe t1s do
    its('status') { should cmp 200 }
  end
  unless t1s.status != 200
    t1sjson = JSON.parse(t1s.body)
    if t1sjson['results'] == []
      describe 'No T1 Gateways are deployed...skipping...' do
        skip 'No T1 Gateways are deployed...skipping...'
      end
    else
      t1sjson['results'].each do |t1|
        t1id = t1['id']
        # Get locale-services id for T0
        t1lss = http("https://#{input('nsxManager')}/policy/api/v1/infra/tier-1s/#{t1id}/locale-services",
                      method: 'GET',
                      headers: {
                        'Accept' => 'application/json',
                        'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                        'Cookie' => "#{input('sessionCookieId')}",
                        },
                      ssl_verify: false)

        t1lssjson = JSON.parse(t1lss.body)
        next unless t1lssjson['result_count'] != 0
        t1lssjson['results'].each do |t1ls|
          t1lsid = t1ls['id']
          # See if multicast is enabled on the T1 itself
          t1mc = http("https://#{input('nsxManager')}/policy/api/v1/infra/tier-1s/#{t1id}/locale-services/#{t1lsid}/multicast",
                        method: 'GET',
                        headers: {
                          'Accept' => 'application/json',
                          'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                          'Cookie' => "#{input('sessionCookieId')}",
                          },
                        ssl_verify: false)

          t1mcjson = JSON.parse(t1mc.body)

          # 200 is returned if successfull and multicast has ever been enabled on the T0 otherwise we get a 404 and can assume disabled
          if t1mc.status == 200
            # If multicast is enabled on the T0 it should be in the list so we can determine if any interfaces should have it enabled
            if t1mcjson['enabled']
              describe t1id do
                it { should be_in input('t1multicastlist') }
              end
              describe t1mcjson['enabled'] do
                it { should cmp 'true' }
              end
            # If multicast is not enabled on the T0 then no interfaces should have it enabled
            else
              describe t1mcjson['enabled'] do
                it { should cmp 'false' }
              end
            end
          # If 404 is returned then multicast has never been abled on the T0 and all interfaces should not have it enabled
          else
            describe t1mc do
              its('status') { should cmp 404 }
            end
          end
        end
      end
    end
  end
end
