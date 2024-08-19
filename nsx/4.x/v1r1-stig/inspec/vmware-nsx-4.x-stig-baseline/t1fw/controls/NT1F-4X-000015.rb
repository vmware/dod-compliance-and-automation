control 'NT1F-4X-000015' do
  title 'The NSX Tier-1 Gateway firewall must manage excess bandwidth to limit the effects of packet flooding types of denial-of-service (DoS) attacks.'
  desc %q(A firewall experiencing a DoS attack will not be able to handle production traffic load. The high usage and CPU caused by a DoS attack will also have an effect on control keep-alives and timers used for neighbor peering resulting in route flapping and will eventually black hole production traffic.

The device must be configured to contain and limit a DoS attack's effect on the device's resource usage. The use of redundant components and load balancing are examples of mitigating "flood-type" DoS attacks through increased capacity.)
  desc 'check', '
    From the NSX Manager web interface, go to Security >> Settings >> General Settings >> Firewall >> Flood Protection to view Flood Protection profiles.

    If there are no Flood Protection profiles of type "Gateway", this is a finding.

    For each gateway flood protection profile, if TCP Half Open Connection limit, UDP Active Flow Limit, ICMP Active Flow Limit, and Other Active Connection Limit are set to "None", this is a finding.

    For each gateway flood protection profile, examine the "Applied To" field to view the Tier-1 Gateways to which it is applied.

    If a gateway flood protection profile is not applied to all Tier-1 Gateways through one or more policies, this is a finding.
  '
  desc 'fix', 'To create a new Flood Protection profile, do the following:

From the NSX Manager web interface, go to Security >> Settings >> General Settings >> Firewall >> Flood Protection >> Add Profile >> Add Firewall Profile.

Enter a name and specify appropriate values for the following: TCP Half Open Connection limit, UDP Active Flow Limit, ICMP Active Flow Limit, and Other Active Connection Limit.

Configure the "Applied To" field to contain Tier-1 Gateways and then click "Save".'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-NET-000193-FW-000030'
  tag satisfies: ['SRG-NET-000192-FW-000029', 'SRG-NET-000362-FW-000028']
  tag gid: 'V-263405'
  tag rid: 'SV-263405r977982_rule'
  tag stig_id: 'NT1F-4X-000015'
  tag cci: ['CCI-001094', 'CCI-001095', 'CCI-002385']
  tag nist: ['SC-5', 'SC-5 (1)', 'SC-5 (2)', 'SC-5 a']

  t1s = http("https://#{input('nsxManager')}/policy/api/v1/infra/tier-1s",
             method: 'GET',
             headers: {
               'Accept' => 'application/json',
               'X-XSRF-TOKEN' => "#{input('sessionToken')}",
               'Cookie' => "#{input('sessionCookieId')}"
             },
             ssl_verify: false)

  describe t1s do
    its('status') { should cmp 200 }
  end
  unless t1s.status != 200
    t1sjson = JSON.parse(t1s.body)
    if t1sjson['results'] == []
      impact 0.0
      describe 'No T1 Gateways are deployed. This is Not Applicable.' do
        skip 'No T1 Gateways are deployed. This is Not Applicable.'
      end
    else
      t1sjson['results'].each do |t1|
        t1json = json(content: t1.to_json)
        t1id = t1json['id']
        t1gfpp = http("https://#{input('nsxManager')}/policy/api/v1/infra/tier-1s/#{t1id}/flood-protection-profile-bindings/default",
                      method: 'GET',
                      headers: {
                        'Accept' => 'application/json',
                        'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                        'Cookie' => "#{input('sessionCookieId')}"
                      },
                      ssl_verify: false)

        if t1gfpp.status == 200
          t1gfppjson = JSON.parse(t1gfpp.body)
          describe "Found Gateway Flood Protection Profile binding for T1: #{t1json['display_name']}" do
            subject { t1gfppjson }
            its(['profile_path']) { should_not be nil }
          end
        else
          describe "No Gateway Flood Protection Profile binding found for T1: #{t1json['display_name']}" do
            subject { t1gfpp }
            its('status') { should cmp 200 }
          end
        end
      end

      result = http("https://#{input('nsxManager')}/policy/api/v1/search?query=( resource_type:( GatewayFloodProtectionProfile ))",
                    method: 'GET',
                    headers: {
                      'Accept' => 'application/json',
                      'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                      'Cookie' => "#{input('sessionCookieId')}"
                    },
                    ssl_verify: false)

      describe result do
        its('status') { should cmp 200 }
      end
      unless result.status != 200
        gfpps = JSON.parse(result.body)
        if gfpps['results'] == []
          describe 'No gateway flood protection profiles found!' do
            subject { gfpps['results'] }
            it { should_not cmp [] }
          end
        else
          gfpps['results'].each do |item|
            gfppid = item['id']
            gfpp = http("https://#{input('nsxManager')}/policy/api/v1/infra/flood-protection-profiles/#{gfppid}",
                        method: 'GET',
                        headers: {
                          'Accept' => 'application/json',
                          'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                          'Cookie' => "#{input('sessionCookieId')}"
                        },
                        ssl_verify: false)

            describe gfpp do
              its('status') { should cmp 200 }
            end
            next unless gfpp.status == 200
            details = JSON.parse(gfpp.body)
            describe details do
              its(['udp_active_flow_limit']) { should_not cmp nil }
              its(['icmp_active_flow_limit']) { should_not cmp nil }
              its(['tcp_half_open_conn_limit']) { should_not cmp nil }
              its(['other_active_conn_limit']) { should_not cmp nil }
            end
          end
        end
      end
    end
  end
end
