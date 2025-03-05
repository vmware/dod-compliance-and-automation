control 'NT0R-4X-000027' do
  title 'The NSX Tier-0 Gateway router must be configured to have the Dynamic Host Configuration Protocol (DHCP) service disabled if not in use.'
  desc 'A compromised router introduces risk to the entire network infrastructure, as well as data resources that are accessible via the network. The perimeter defense has no oversight or control of attacks by malicious users within the network. Preventing network breaches from within is dependent on implementing a comprehensive defense-in-depth strategy, including securing each device connected to the network. This is accomplished by following and implementing all security guidance applicable for each node type. A fundamental step in securing each router is to enable only the capabilities required for operation.'
  desc 'check', 'From the NSX Manager web interface, go to Networking >> Connectivity >> Tier-0 Gateways.

For every Tier-0 Gateway, expand the Tier-0 Gateway to view the DHCP configuration.

If a DHCP profile is configured and not in use, this is a finding.'
  desc 'fix', 'From the NSX Manager web interface, go to Networking >> Connectivity >> Tier-0 Gateways and edit the target Tier-0 gateway.

Click "Set DHCP Configuration", select "No Dynamic IP Address Allocation", and then click "Save". Close "Editing".'
  impact 0.3
  ref 'DPMS Target VMware NSX 4.x Tier-0 Gateway Router'
  tag check_id: 'C-69321r994560_chk'
  tag severity: 'low'
  tag gid: 'V-265404'
  tag rid: 'SV-265404r999914_rule'
  tag stig_id: 'NT0R-4X-000027'
  tag gtitle: 'SRG-NET-000131-RTR-000035'
  tag fix_id: 'F-69229r999914_fix'
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
        if t0['dhcp_config_paths'].nil?
          describe t0 do
            its(['dhcp_config_paths']) { should be nil }
          end
        else
          describe t0 do
            its(['id']) { should be_in input('t0dhcplist') }
          end
        end
      end
    end
  end
end
