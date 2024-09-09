control 'NT0R-4X-000064' do
  title 'The NSX Tier-0 Gateway router must be configured to have Internet Control Message Protocol (ICMP) unreachable notifications disabled on all external interfaces.'
  desc 'The ICMP supports IP traffic by relaying information about paths, routes, and network conditions. Routers automatically send ICMP messages under a wide variety of conditions. Host unreachable ICMP messages are commonly used by attackers for network mapping and diagnosis.'
  desc 'check', '
    If the Tier-0 Gateway is deployed in an Active/Active HA mode, this is Not Applicable.

    From the NSX Manager web interface, go to Security >> Policy Management >> Gateway Firewall >> Gateway Specific Rules, and choose each Tier-0 Gateway in the drop-down.

    Review each Tier-0 Gateway Firewall rule to verify one exists to drop ICMP unreachable messages.

    If a rule does not exist to drop ICMP unreachable messages, this is a finding.
  '
  desc 'fix', 'To configure a shared rule to drop ICMP unreachable messages, do the following:

From the NSX Manager web interface, go to Security >> Policy Management >> Gateway Firewall >> All Shared Rules.

Click "Add Rule" (add a policy first, if needed) and under "Services", select "ICMP Destination Unreachable" and "Apply".

Enable logging and under the "Applied To" field select the target Tier-0 Gateways and click "Publish" to enforce the new rule.

Note: A rule can also be created under Gateway Specific Rules to meet this requirement.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000362-RTR-000113'
  tag gid: 'V-263305'
  tag rid: 'SV-263305r977682_rule'
  tag stig_id: 'NT0R-4X-000064'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5', 'SC-5 a']

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
      # Check shared rules first
      sharedgwpols = http("https://#{input('nsxManager')}/policy/api/v1/search?query=(resource_type:GatewayPolicy%20AND%20category:SharedPreRules)",
                          method: 'GET',
                          headers: {
                            'Accept' => 'application/json',
                            'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                            'Cookie' => "#{input('sessionCookieId')}"
                          },
                          ssl_verify: false)

      describe sharedgwpols do
        its('status') { should cmp 200 }
      end
      next unless sharedgwpols.status == 200
      sharedgwpolsjson = JSON.parse(sharedgwpols.body)
      sharedicmprulefound = false
      icmprulefound = false
      nonactiveactivegwfound = false
      sharedgwpolsjson['results'].each do |sharedpol|
        sharedpoljson = json(content: sharedpol.to_json)
        sharedpolpath = sharedpoljson['path']
        sharedrules = http("https://#{input('nsxManager')}/policy/api/v1#{sharedpolpath}",
                           method: 'GET',
                           headers: {
                             'Accept' => 'application/json',
                             'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                             'Cookie' => "#{input('sessionCookieId')}"
                           },
                           ssl_verify: false)

        describe sharedrules do
          its('status') { should cmp 200 }
        end
        next unless sharedrules.status == 200
        sharedrulesjson = JSON.parse(sharedrules.body)
        sharedrulesjson['rules'].each do |rule|
          next unless rule['services'].include? '/infra/services/ICMP_Destination_Unreachable'
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
          nonactiveactivegwfound = true
          gwfw = http("https://#{input('nsxManager')}/policy/api/v1/infra/tier-0s/#{t0id}/gateway-firewall",
                      method: 'GET',
                      headers: {
                        'Accept' => 'application/json',
                        'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                        'Cookie' => "#{input('sessionCookieId')}"
                      },
                      ssl_verify: false)

          describe gwfw do
            its('status') { should cmp 200 }
          end
          next unless gwfw.status == 200
          gwfwjson = JSON.parse(gwfw.body)
          gwfwjson['results'].each do |res|
            res['rules'].each do |rule|
              next unless rule['services'].include? '/infra/services/ICMP_Destination_Unreachable'
              icmprulefound = true
              describe rule do
                its(['action']) { should_not cmp 'ALLOW' }
              end
            end
          end
          describe 'A firewall rule should exist with a rule to drop ICMP unreachable traffic' do
            subject { icmprulefound }
            it { should cmp true }
          end
        end
      end
      unless sharedicmprulefound && nonactiveactivegwfound
        impact 0.0
        describe 'No T0 Gateways found that are not Active/Active so this is Not Applicable.' do
          skip 'No T0 Gateways found that are not Active/Active so this is Not Applicable.'
        end
      end
    end
  end
end
