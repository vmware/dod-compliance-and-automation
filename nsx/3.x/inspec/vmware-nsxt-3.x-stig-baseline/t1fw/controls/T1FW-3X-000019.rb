control 'T1FW-3X-000019' do
  title 'The NSX-T Tier-1 Gateway Firewall must block outbound traffic containing denial-of-service (DoS) attacks to protect against the use of internal information systems to launch any DoS attacks against other networks or endpoints.'
  desc 'DoS attacks can take multiple forms but have the common objective of overloading or blocking a network or host to deny or seriously degrade performance. If the network does not provide safeguards against DoS attacks, network resources will be unavailable to users.

Installation of a firewall at key boundaries in the architecture mitigates the risk of DoS attacks. These attacks can be detected by matching observed communications traffic with patterns of known attacks and monitoring for anomalies in traffic volume/type.

The firewall must include protection against DoS attacks that originate from inside the enclave that can affect either internal or external systems. These attacks may use legitimate or rogue endpoints from inside the enclave. These attacks can be simple "floods" of traffic to saturate circuits or devices, malware that consumes CPU and memory on a device or causes it to crash, or a configuration issue that disables or impairs the proper function of a device. For example, an accidental or deliberate misconfiguration of a routing table can misdirect traffic for multiple networks.

'
  desc 'check', 'From the NSX-T Manager web interface, go to Security >> General Settings >> Firewall >> Flood Protection to view Flood Protection profiles.

If there are no Flood Protection profiles of type "Gateway", this is a finding.

For each gateway flood protection profile, verify the TCP Half Open Connection limit, UDP Active Flow Limit, ICMP Active Flow Limit, and Other Active Connection Limit are set to "None".

If they are not, this is a finding.

For each gateway flood protection profile, examine the "Applied To" field to view the Tier-1 Gateways to which it is applied.

If a gateway flood protection profile is not applied to all Tier-1 Gateways through one or more policies, this is a finding.'
  desc 'fix', 'To create a new Flood Protection profile, do the following:

From the NSX-T Manager web interface, go to Security >> General Settings >> Firewall >> Flood Protection >> Add Profile >> Add Firewall Profile.

Enter a name and specify appropriate values for the following: TCP Half Open Connection limit, UDP Active Flow Limit, ICMP Active Flow Limit, and Other Active Connection Limit.

Configure the "Applied To" field to contain Tier-1 Gateways and then click "Save".'
  impact 0.5
  tag check_id: 'C-55201r919238_chk'
  tag severity: 'medium'
  tag gid: 'V-251764'
  tag rid: 'SV-251764r919240_rule'
  tag stig_id: 'T1FW-3X-000019'
  tag gtitle: 'SRG-NET-000192-FW-000029'
  tag fix_id: 'F-55155r919239_fix'
  tag satisfies: ['SRG-NET-000192-FW-000029', 'SRG-NET-000193-FW-000030']
  tag cci: ['CCI-001094', 'CCI-001095']
  tag nist: ['SC-5 (1)', 'SC-5 (2)']

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
        t1json = json(content: t1.to_json)
        t1id = t1json['id']
        t1gfpp = http("https://#{input('nsxManager')}/policy/api/v1/infra/tier-1s/#{t1id}/flood-protection-profile-bindings/default",
                 method: 'GET',
                 headers: {
                   'Accept' => 'application/json',
                   'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                   'Cookie' => "#{input('sessionCookieId')}",
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
                  'Cookie' => "#{input('sessionCookieId')}",
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
                        'Cookie' => "#{input('sessionCookieId')}",
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
