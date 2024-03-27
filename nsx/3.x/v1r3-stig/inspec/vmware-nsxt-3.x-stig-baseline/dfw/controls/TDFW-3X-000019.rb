control 'TDFW-3X-000019' do
  title 'The NSX-T Distributed Firewall must block outbound traffic containing denial-of-service (DoS) attacks to protect against the use of internal information systems to launch any DoS attacks against other networks or endpoints.'
  desc 'DoS attacks can take multiple forms but have the common objective of overloading or blocking a network or host to deny or seriously degrade performance. If the network does not provide safeguards against DoS attacks, network resources will be unavailable to users.

Installation of a firewall at key boundaries in the architecture mitigates the risk of DoS attacks. These attacks can be detected by matching observed communications traffic with patterns of known attacks and monitoring for anomalies in traffic volume/type.

The firewall must include protection against DoS attacks that originate from inside the enclave that can affect either internal or external systems. These attacks may use legitimate or rogue endpoints from inside the enclave. These attacks can be simple "floods" of traffic to saturate circuits or devices, malware that consumes CPU and memory on a device or causes it to crash, or a configuration issue that disables or impairs the proper function of a device. For example, an accidental or deliberate misconfiguration of a routing table can misdirect traffic for multiple networks.

'
  desc 'check', 'From the NSX-T Manager web interface, go to Security >> General Settings >> Firewall >> Flood Protection to view Flood Protection profiles.

If there are no Flood Protection profiles of type "Distributed Firewall", this is a finding.

If the TCP Half Open Connection limit, UDP Active Flow Limit, ICMP Active Flow Limit, and Other Active Connection Limit are set to "not set" or SYN Cache and RST Spoofing are not enabled on a profile, this is a finding.

For each distributed firewall flood protection profile, examine the "Applied To" field to view the workloads it is protecting.

If a distributed firewall flood protection profile is not applied to all workloads through one or more policies, this is a finding.'
  desc 'fix', 'To create a new Flood Protection profile, do the following:

From the NSX-T Manager web interface, go to Security >> General Settings >> Firewall >> Flood Protection >> Add Profile >> Add Firewall Profile.

Enter a name and specify appropriate values for the following: TCP Half Open Connection limit, UDP Active Flow Limit, ICMP Active Flow Limit, and Other Active Connection Limit.

Enable SYN Cache and RST Spoofing, configure the "Applied To" field with the appropriate security groups, and click "Save".'
  impact 0.5
  tag check_id: 'C-55165r919498_chk'
  tag severity: 'medium'
  tag gid: 'V-251728'
  tag rid: 'SV-251728r919499_rule'
  tag stig_id: 'TDFW-3X-000019'
  tag gtitle: 'SRG-NET-000192-FW-000029'
  tag fix_id: 'F-55119r919499_fix'
  tag satisfies: ['SRG-NET-000192-FW-000029', 'SRG-NET-000193-FW-000030']
  tag cci: ['CCI-001094', 'CCI-001095']
  tag nist: ['SC-5 (1)', 'SC-5 (2)']

  result = http("https://#{input('nsxManager')}/policy/api/v1/search?query=(resource_type:DistributedFloodProtectionProfile)",
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
