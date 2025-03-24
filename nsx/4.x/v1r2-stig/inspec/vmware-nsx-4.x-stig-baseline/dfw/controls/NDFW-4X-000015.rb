control 'NDFW-4X-000015' do
  title 'The NSX Distributed Firewall must limit the effects of packet flooding types of denial-of-service (DoS) attacks.'
  desc %q(A firewall experiencing a DoS attack will not be able to handle production traffic load. The high utilization and CPU caused by a DoS attack will also have an effect on control keep-alives and timers used for neighbor peering resulting in route flapping and will eventually black hole production traffic.

The device must be configured to contain and limit a DoS attack's effect on the device's resource utilization. The use of redundant components and load balancing are examples of mitigating "flood-type" DoS attacks through increased capacity.

)
  desc 'check', 'From the NSX Manager web interface, navigate to Security >> Settings >> General Settings >> Firewall >> Flood Protection to view Flood Protection profiles.

If there are no Flood Protection profiles of type "Distributed Firewall", this is a finding.

If the TCP Half Open Connection limit, UDP Active Flow Limit, ICMP Active Flow Limit, and Other Active Connection Limit are "not set" or SYN Cache and RST Spoofing is not Enabled on a profile, this is a finding.

For each distributed firewall flood protection profile, examine the "Applied To" field to view the workloads it is protecting.

If a distributed firewall flood protection profile is not applied to all workloads through one or more policies, this is a finding.'
  desc 'fix', 'To create a new Flood Protection profile:

From the NSX Manager web interface, navigate to Security >> Settings >> General Settings >> Firewall >> Flood Protection >> Add Profile >> Add Firewall Profile.

Enter a name and specify appropriate values for the following: TCP Half Open Connection limit, UDP Active Flow Limit, ICMP Active Flow Limit, and Other Active Connection Limit.

Enable SYN Cache and RST Spoofing, configure the "Applied To" field with the appropriate security groups, and click "Save".'
  impact 0.5
  ref 'DPMS Target VMware NSX 4.x Distributed Firewall'
  tag check_id: 'C-69535r993949_chk'
  tag severity: 'medium'
  tag gid: 'V-265618'
  tag rid: 'SV-265618r993951_rule'
  tag stig_id: 'NDFW-4X-000015'
  tag gtitle: 'SRG-NET-000193-FW-000030'
  tag fix_id: 'F-69443r993950_fix'
  tag satisfies: ['SRG-NET-000193-FW-000030', 'SRG-NET-000192-FW-000029', 'SRG-NET-000362-FW-000028']
  tag 'documentable'
  tag cci: ['CCI-001095', 'CCI-001094', 'CCI-002385']
  tag nist: ['SC-5 (2)', 'SC-5 (1)', 'SC-5 a']

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
