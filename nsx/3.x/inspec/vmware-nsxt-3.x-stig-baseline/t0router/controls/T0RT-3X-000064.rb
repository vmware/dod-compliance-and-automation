control 'T0RT-3X-000064' do
  title 'The NSX-T Tier-0 Gateway must be configured to have Internet Control Message Protocol (ICMP) unreachable notifications disabled on all external interfaces.'
  desc  'The ICMP supports IP traffic by relaying information about paths, routes, and network conditions. Routers automatically send ICMP messages under a wide variety of conditions. Host unreachable ICMP messages are commonly used by attackers for network mapping and diagnosis.'
  desc  'rationale', ''
  desc  'check', "
    If the Tier-0 Gateway is deployed in an Active/Active HA mode, this is Not Applicable.

    From the NSX-T Manager web interface, go to Security >> Gateway Firewall >> Gateway Specific Rules, and choose each Tier-0 Gateway in the drop-down.

    Review each Tier-0 Gateway Firewall rule to verify one exists to drop ICMP unreachable messages.

    If a rule does not exist to drop ICMP unreachable messages, this is a finding.
  "
  desc 'fix', "
    If the Tier-0 Gateway is deployed in an Active/Active HA mode, this is Not Applicable.

    From the NSX-T Manager web interface, go to Security >> Gateway Firewall >> Gateway Specific Rules, and choose each Tier-0 Gateway in the drop-down.

    Review each Tier-0 Gateway Firewall rule to verify one exists to drop ICMP unreachable messages.

    If a rule does not exist to drop ICMP unreachable messages, this is a finding.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000362-RTR-000113'
  tag gid: 'V-251753'
  tag rid: 'SV-251753r856694_rule'
  tag stig_id: 'T0RT-3X-000064'
  tag fix_id: 'F-55144r810142_fix'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5']

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
      # Check shared rules first
      sharedgwpols = http("https://#{input('nsxManager')}/policy/api/v1/search?query=(resource_type:GatewayPolicy%20AND%20category:SharedPreRules)",
                        method: 'GET',
                        headers: {
                          'Accept' => 'application/json',
                          'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                          'Cookie' => "#{input('sessionCookieId')}",
                          },
                        ssl_verify: false)

      describe sharedgwpols do
        its('status') { should cmp 200 }
      end
      next unless sharedgwpols.status == 200
      sharedgwpolsjson = JSON.parse(sharedgwpols.body)
      sharedicmprulefound = false
      sharedgwpolsjson['results'].each do |sharedpol|
        sharedpoljson = json(content: sharedpol.to_json)
        sharedpolpath = sharedpoljson['path']
        sharedrules = http("https://#{input('nsxManager')}/policy/api/v1#{sharedpolpath}",
                        method: 'GET',
                        headers: {
                          'Accept' => 'application/json',
                          'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                          'Cookie' => "#{input('sessionCookieId')}",
                          },
                        ssl_verify: false)

        describe sharedrules do
          its('status') { should cmp 200 }
        end
        next unless sharedrules.status == 200
        sharedrulesjson = JSON.parse(sharedrules.body)
        sharedrulesjson['rules'].each do |rule|
          next unless rule['services'].include?'/infra/services/ICMP_Destination_Unreachable'
          sharedicmprulefound = true
          describe rule do
            its(['action']) { should_not cmp 'ALLOW' }
          end
        end
      end
      # If shared rule not found check gateway specific rules
      unless sharedicmprulefound
        t0sjson['results'].each do |t0|
          t0id = t0['id']
          next unless t0['ha_mode'] != 'ACTIVE_ACTIVE'
          gwfw = http("https://#{input('nsxManager')}/policy/api/v1/infra/tier-0s/#{t0id}/gateway-firewall",
                    method: 'GET',
                    headers: {
                      'Accept' => 'application/json',
                      'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                      'Cookie' => "#{input('sessionCookieId')}",
                      },
                    ssl_verify: false)

          describe gwfw do
            its('status') { should cmp 200 }
          end
          next unless gwfw.status == 200
          gwfwjson = JSON.parse(gwfw.body)
          icmprulefound = false
          gwfwjson['results'].each do |res|
            res['rules'].each do |rule|
              next unless rule['services'].include?'/infra/services/ICMP_Destination_Unreachable'
              icmprulefound = true
              describe rule do
                its(['action']) { should_not cmp 'ALLOW' }
              end
            end
          end
          describe 'A firewall rule should exist with a rule to drop ICMP unreachable traffic' do
            subject { icmprulefound }
            it { should eq true }
          end
        end
      end
    end
  end
end
