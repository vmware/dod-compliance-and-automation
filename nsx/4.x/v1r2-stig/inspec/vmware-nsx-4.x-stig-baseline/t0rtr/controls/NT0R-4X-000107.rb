control 'NT0R-4X-000107' do
  title 'The NSX Tier-0 Gateway router must be configured to have multicast disabled if not in use.'
  desc 'A compromised router introduces risk to the entire network infrastructure, as well as data resources that are accessible via the network. The perimeter defense has no oversight or control of attacks by malicious users within the network. Preventing network breaches from within is dependent on implementing a comprehensive defense-in-depth strategy, including securing each device connected to the network. This is accomplished by following and implementing all security guidance applicable for each node type. A fundamental step in securing each router is to enable only the capabilities required for operation.'
  desc 'check', 'From the NSX Manager web interface, go to Networking >> Connectivity >> Tier-0 Gateways.

For every Tier-0 Gateway, expand the Tier-0 Gateway, then expand "Multicast" to view the multicast configuration.

If multicast is enabled and not in use, this is a finding.'
  desc 'fix', 'If not used, disable Multicast by doing the following:

From the NSX Manager web interface, go to Networking >> Connectivity >> Tier-0 Gateways and edit the target Tier-0 gateway.

Expand Multicast, change from "Enabled" to "Disabled", and then click "Save".'
  impact 0.3
  ref 'DPMS Target VMware NSX 4.x Tier-0 Gateway Router'
  tag check_id: 'C-69401r994800_chk'
  tag severity: 'low'
  tag gid: 'V-265484'
  tag rid: 'SV-265484r999919_rule'
  tag stig_id: 'NT0R-4X-000107'
  tag gtitle: 'SRG-NET-000131-RTR-000035'
  tag fix_id: 'F-69309r999919_fix'
  tag 'documentable'
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
          # See if multicast is enabled on the T0 itself
          t0mc = http("https://#{input('nsxManager')}/policy/api/v1/infra/tier-0s/#{t0id}/locale-services/#{t0lsid}/multicast",
                      method: 'GET',
                      headers: {
                        'Accept' => 'application/json',
                        'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                        'Cookie' => "#{input('sessionCookieId')}"
                      },
                      ssl_verify: false)

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
            # If multicast is not enabled on the T0 then no interfaces should have it enabled
            else
              describe t0mcjson['enabled'] do
                it { should cmp 'false' }
              end
            end
          # If 404 is returned then multicast has never been abled on the T0 and all interfaces should not have it enabled
          else
            describe t0mc do
              its('status') { should cmp 404 }
            end
          end
        end
      end
    end
  end
end
