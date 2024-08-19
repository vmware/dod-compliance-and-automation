control 'NT1R-4X-000027' do
  title 'The NSX Tier-1 Gateway router must be configured to have the DHCP service disabled if not in use.'
  desc 'A compromised router introduces risk to the entire network infrastructure, as well as data resources that are accessible via the network. The perimeter defense has no oversight or control of attacks by malicious users within the network. Preventing network breaches from within is dependent on implementing a comprehensive defense-in-depth strategy, including securing each device connected to the network. This is accomplished by following and implementing all security guidance applicable for each node type. A fundamental step in securing each router is to enable only the capabilities required for operation.'
  desc 'check', '
    From the NSX Manager web interface, go to Networking >> Connectivity >> Tier-1 Gateways.

    For every Tier-1 Gateway expand the Tier-1 Gateway to view the DHCP configuration.

    If a DHCP profile is configured and not in use, this is a finding.
  '
  desc 'fix', '
    From the NSX Manager web interface, go to Networking >> Connectivity >> Tier-1 Gateways and edit the target Tier-1 Gateway.

    Click "Set DHCP Configuration", select "No Dynamic IP Address Allocation", click "Save", and then close "Editing".
  '
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000131-RTR-000035'
  tag gid: 'V-263424'
  tag rid: 'SV-263424r978039_rule'
  tag stig_id: 'NT1R-4X-000027'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

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
        if t1['dhcp_config_paths'].nil?
          describe t1 do
            its(['dhcp_config_paths']) { should be nil }
          end
        else
          describe t1 do
            its(['id']) { should be_in input('t1dhcplist') }
          end
        end
      end
    end
  end
end
