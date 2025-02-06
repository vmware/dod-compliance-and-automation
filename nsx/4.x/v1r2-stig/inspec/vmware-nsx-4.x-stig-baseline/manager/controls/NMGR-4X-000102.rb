control 'NMGR-4X-000102' do
  title 'The NSX Manager must be configured as a cluster.'
  desc 'Failure in a known state can address safety or security in accordance with the mission needs of the organization. Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the SDN controller. Preserving network element state information helps to facilitate continuous network operations minimal or no disruption to mission-essential workload processes and flows.'
  desc 'check', 'From the NSX Manager web interface, go to System >> Configuration >> Appliances.

Verify three NSX Managers are deployed, a VIP or external load balancer is configured, and the cluster is in a healthy state.

If three NSX Managers are not deployed, a VIP or external load balancer is not configured, and the cluster is not in a healthy state, this is a finding.'
  desc 'fix', %q(To add additional NSX Manager appliances do the following:

From the NSX Manager web interface, go to System >> Configuration >> Appliances, and then click "Add NSX Appliance".

Supply the required information to add additional nodes as needed, up to three total.

To configure NSX with a cluster VIP or external load balancer, do the following:

From the NSX Manager web interface, go to System >> Configuration >> Appliances, and then click "Set Virtual IP", enter a VIP that is part of the same subnet as the other management nodes, and then click "Save".

To configure NSX with an external load balancer, setup an external load balancer with the following requirements:

- Configure the external load balancer to control traffic to the NSX Manager nodes.
- Configure the external load balancer to use the round robin method and configure source persistence for the load balancer's virtual IP.
- Create or import a signed certificate and apply the same certificate to all the NSX Manager nodes. The certificate must have the FQDN of the virtual IP and each of the nodes in the SAN.

Note: An external load balancer will not work with the NSX Manager VIP. Do not configure an NSX Manager VIP if using an external load balancer.

If the cluster status is not in a healthy state, identify the degraded component on the appliance and troubleshoot the issue with the error information provided.)
  impact 0.5
  ref 'DPMS Target VMware NSX 4.x Manager NDM'
  tag check_id: 'C-69275r994295_chk'
  tag severity: 'medium'
  tag gid: 'V-265358'
  tag rid: 'SV-265358r994297_rule'
  tag stig_id: 'NMGR-4X-000102'
  tag gtitle: 'SRG-APP-000435-NDM-000315'
  tag fix_id: 'F-69183r994296_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']

  result = http("https://#{input('nsxManager')}/api/v1/cluster/status",
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
    j = JSON.parse(result.body)
    describe 'Cluster status' do
      subject { j }
      its(['control_cluster_status', 'status']) { should cmp 'STABLE' }
    end
    c = j['mgmt_cluster_status']['online_nodes']
    describe c do
      its('size') { should eq 3 }
    end
  end

  result = http("https://#{input('nsxManager')}/api/v1/cluster/api-virtual-ip",
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
    describe.one do
      describe json(content: result.body) do
        its('ip_address') { should_not be_empty }
        its('ip_address') { should_not cmp '0.0.0.0' }
      end
      describe json(content: result.body) do
        its('ip6_address') { should_not be_empty }
        its('ip6_address') { should_not cmp '::' }
      end
    end
  end
end
