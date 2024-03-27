control 'T0FW-3X-000028' do
  title 'The NSX-T Tier-0 Gateway Firewall must employ filters that prevent or limit the effects of all types of commonly known denial-of-service (DoS) attacks, including flooding, packet sweeps, and unauthorized port scanning.'
  desc "Not configuring a key boundary security protection device, such as the firewall, against commonly known attacks is an immediate threat to the protected enclave because they are easily implemented by those with little skill. Directions for the attack are obtainable on the internet and in hacker groups. Without filtering enabled for these attacks, the firewall will allow these attacks beyond the protected boundary.

Configure the perimeter and internal boundary firewall to guard against the three general methods of well-known DoS attacks: flooding attacks, protocol sweeping attacks, and unauthorized port scanning.

Flood attacks occur when the host receives too much traffic to buffer and it slows down or crashes. Popular flood attacks include ICMP flood and SYN flood. A TCP flood attack of SYN packets initiating connection requests can overwhelm the device until it can no longer process legitimate connection requests, resulting in denial of service. An ICMP flood can overload the device with so many echo requests (ping requests) that it expends all its resources responding and can no longer process valid network traffic, also resulting in denial of service. An attacker might use session table floods and SYN-ACK-ACK proxy floods to fill up the session table of a host.

In an IP address sweep attack, an attacker sends ICMP echo requests (pings) to multiple destination addresses. If a target host replies, the reply reveals the target's IP address to the attacker. In a TCP sweep attack, an attacker sends TCP SYN packets to the target device as part of the TCP handshake. If the device responds to those packets, the attacker gets an indication that a port in the target device is open, which makes the port vulnerable to attack. In a UDP sweep attack, an attacker sends UDP packets to the target device. If the device responds to those packets, the attacker gets an indication that a port in the target device is open, which makes the port vulnerable to attack.

In a port scanning attack, an unauthorized application is used to scan the host devices for available services and open ports for subsequent use in an attack. This type of scanning can be used as a DoS attack when the probing packets are sent excessively."
  desc 'check', 'If the Tier-0 Gateway is deployed in an Active/Active HA mode and no stateless rules exist, this is Not Applicable.

From the NSX-T Manager web interface, go to Security >> Security Profiles >> Flood Protection to view Flood Protection profiles.

If there are no Flood Protection profiles of type "Gateway", this is a finding.

For each gateway flood protection profile, verify the TCP Half Open Connection limit, UDP Active Flow Limit, ICMP Active Flow Limit, and Other Active Connection Limit are set to "not set" or SYN Cache and RST Spoofing is not "Enabled" on a profile, this is a finding.

For each gateway flood protection profile, examine the Applied To field to view the Tier-0 Gateways to which it is applied.

If a gateway flood protection profile is not applied to all Tier-0 Gateways through one or more policies, this is a finding.'
  desc 'fix', 'To create a new Flood Protection profile, do the following:

From the NSX-T Manager web interface, go to Security >> Security Profiles >> Flood Protection >> Add Profile >> Add Firewall Profile.

Enter a name and specify appropriate values for the following: TCP Half Open Connection limit, UDP Active Flow Limit, ICMP Active Flow Limit, and Other Active Connection Limit.

Enable SYN Cache and RST Spoofing, then configure the Applied To field to contain Tier-0 Gateways and click "Save".'
  impact 0.5
  tag check_id: 'C-55178r810088_chk'
  tag severity: 'medium'
  tag gid: 'V-251741'
  tag rid: 'SV-251741r856690_rule'
  tag stig_id: 'T0FW-3X-000028'
  tag gtitle: 'SRG-NET-000362-FW-000028'
  tag fix_id: 'F-55132r810089_fix'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']

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
        t0json = json(content: t0.to_json)
        t0id = t0json['id']
        t0gfpp = http("https://#{input('nsxManager')}/policy/api/v1/infra/tier-0s/#{t0id}/flood-protection-profile-bindings/default",
                      method: 'GET',
                      headers: {
                        'Accept' => 'application/json',
                        'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                        'Cookie' => "#{input('sessionCookieId')}"
                      },
                      ssl_verify: false)

        if t0gfpp.status == 200
          t0gfppjson = JSON.parse(t0gfpp.body)
          describe "Found Gateway Flood Protection Profile binding for T0: #{t0json['display_name']}" do
            subject { t0gfppjson }
            its(['profile_path']) { should_not be nil }
          end
        else
          describe "No Gateway Flood Protection Profile binding found for T0: #{t0json['display_name']}" do
            subject { t0gfpp }
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
