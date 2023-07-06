control 'TDFW-3X-000028' do
  title 'The NSX-T Distributed Firewall must employ filters that prevent or limit the effects of all types of commonly known denial-of-service (DoS) attacks, including flooding, packet sweeps, and unauthorized port scanning.'
  desc  "
    Not configuring a key boundary security protection device, such as the firewall, against commonly known attacks is an immediate threat to the protected enclave because they are easily implemented by those with little skill. Directions for the attack are obtainable on the internet and in hacker groups. Without filtering enabled for these attacks, the firewall will allow these attacks beyond the protected boundary.

    Configure the perimeter and internal boundary firewall to guard against the three general methods of well-known DoS attacks: Flooding attacks, protocol sweeping attacks, and unauthorized port scanning.

    Flood attacks occur when the host receives too much traffic to buffer and slows down or crashes. Popular flood attacks include ICMP flood and SYN flood. A TCP flood attack of SYN packets initiating connection requests can overwhelm the device until it can no longer process legitimate connection requests, resulting in denial of service. An ICMP flood can overload the device with so many echo requests (ping requests) that it expends all its resources responding and can no longer process valid network traffic, also resulting in denial of service. An attacker might use session table floods and SYN-ACK-ACK proxy floods to fill up the session table of a host.

    In an IP address sweep attack, an attacker sends ICMP echo requests (pings) to multiple destination addresses. If a target host replies, the reply reveals the target's IP address to the attacker. In a TCP sweep attack, an attacker sends TCP SYN packets to the target device as part of the TCP handshake. If the device responds to those packets, the attacker gets an indication that a port in the target device is open, which makes the port vulnerable to attack. In a UDP sweep attack, an attacker sends UDP packets to the target device. If the device responds to those packets, the attacker gets an indication that a port in the target device is open, which makes the port vulnerable to attack.

    In a port scanning attack, an unauthorized application is used to scan the host devices for available services and open ports for subsequent use in an attack. This type of scanning can be used as a DoS attack when the probing packets are sent excessively.
  "
  desc  'rationale', ''
  desc  'check', "
    From the NSX-T Manager web interface, go to Security >> Security Profiles >> Flood Protection to view Flood Protection profiles.

    If there are no Flood Protection profiles of type \"Distributed Firewall\", this is a finding.

    If the TCP Half Open Connection limit, UDP Active Flow Limit, ICMP Active Flow Limit, and Other Active Connection Limit are set to \"not set\" or SYN Cache and RST Spoofing is not Enabled on a profile, this is a finding.

    For each distributed firewall flood protection profile, examine the \"Applied To\" field to view the workloads it is protecting.

    If a distributed firewall flood protection profile is not applied to all workloads through one or more policies, this is a finding.
  "
  desc 'fix', "
    To create a new Flood Protection profile do the following:

    From the NSX-T Manager web interface, go to Security >> Security Profiles >> Flood Protection >> Add Profile >> Add Firewall Profile.

    Enter a name and specify appropriate values for the following: TCP Half Open Connection limit, UDP Active Flow Limit, ICMP Active Flow Limit, and Other Active Connection Limit.

    Enable SYN Cache and RST Spoofing then configure the \"Applied To\" field with the appropriate security groups, and then click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000362-FW-000028'
  tag gid: 'V-251731'
  tag rid: 'SV-251731r856683_rule'
  tag stig_id: 'TDFW-3X-000028'
  tag fix_id: 'F-55122r810046_fix'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5']

  result = http("https://#{input('nsxManager')}/policy/api/v1/search?query=(resource_type:DistributedFloodProtectionProfile)",
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
    describe json(content: result.body) do
      its('result_count') { should cmp > 0 }
    end
    dfpps = JSON.parse(result.body)
    unless dfpps['result_count'] == 0
      dfpps['results'].each do |dfpp|
        id = dfpp['id']
        describe json(content: dfpp.to_json) do
          its('id') { should cmp id }
          its('enable_syncache') { should cmp 'true' }
          its('enable_rst_spoofing') { should cmp 'true' }
          its('udp_active_flow_limit') { should cmp > 0 }
          its('icmp_active_flow_limit') { should cmp > 0 }
          its('tcp_half_open_conn_limit') { should cmp > 0 }
          its('other_active_conn_limit') { should cmp > 0 }
        end
      end
    end
  end
  # Workload protection must be manually verified
  describe 'Part of this check is a manual or policy based check' do
    skip 'For each distributed firewall flood protection profile examine the Applied To field to view the workloads it is protecting.'
  end
end
