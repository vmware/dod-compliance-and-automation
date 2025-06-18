control 'VCFR-9X-000027' do
  title 'The VMware Cloud Foundation NSX Tier-0 Gateway must be configured to have the DHCP service disabled if not in use.'
  desc  'A compromised router introduces risk to the entire network infrastructure, as well as data resources that are accessible via the network. The perimeter defense has no oversight or control of attacks by malicious users within the network. Preventing network breaches from within is dependent on implementing a comprehensive defense-in-depth strategy, including securing each device connected to the network. This is accomplished by following and implementing all security guidance applicable for each node type. A fundamental step in securing each router is to enable only the capabilities required for operation.'
  desc  'rationale', ''
  desc  'check', "
    From the NSX Manager web interface, go to Networking >> Connectivity >> Tier-0 Gateways.

    For every Tier-0 Gateway expand the Tier-0 Gateway to view the DHCP configuration.

    If a DHCP profile is configured and not in use, this is a finding.
  "
  desc 'fix', "
    If not used, disable DHCP by doing the following:

    From the NSX Manager web interface, go to Networking >> Connectivity >> Tier-0 Gateways and edit the target Tier-0 Gateway.

    Click \"Set DHCP Configuration\", select \"No Dynamic IP Address Allocation\", and then click \"Save\". Close \"Editing\".
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-NET-000131-RTR-000035'
  tag gid: 'V-VCFR-9X-000027'
  tag rid: 'SV-VCFR-9X-000027'
  tag stig_id: 'VCFR-9X-000027'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  t0s = http("https://#{input('nsx_managerAddress')}/policy/api/v1/infra/tier-0s",
             method: 'GET',
             headers: {
               'Accept' => 'application/json',
               'X-XSRF-TOKEN' => "#{input('nsx_sessionToken')}",
               'Cookie' => "#{input('nsx_sessionCookieId')}"
             },
             ssl_verify: false)

  describe t0s do
    its('status') { should cmp 200 }
  end
  unless t0s.status != 200
    t0sjson = JSON.parse(t0s.body)
    if t0sjson['result_count'] == 0
      impact 0.0
      describe 'No T0 Gateways are deployed. This is Not Applicable.' do
        skip 'No T0 Gateways are deployed. This is Not Applicable.'
      end
    else
      t0sjson['results'].each do |t0|
        if t0['dhcp_config_paths'].nil?
          describe "T0 Gateway: #{t0['display_name']}" do
            subject { t0 }
            its(['dhcp_config_paths']) { should be nil }
          end
        else
          describe "T0 Gateway: #{t0['display_name']}" do
            subject { t0 }
            its(['id']) { should be_in input('nsx_t0dhcplist') }
          end
        end
      end
    end
  end
end
