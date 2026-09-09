control 'VCFR-9X-000110' do
  title 'The VMware Cloud Foundation NSX Tier-0 Gateway must be configured to have multicast disabled if not in use.'
  desc  'A compromised router introduces risk to the entire network infrastructure, as well as data resources that are accessible via the network. The perimeter defense has no oversight or control of attacks by malicious users within the network. Preventing network breaches from within is dependent on implementing a comprehensive defense-in-depth strategy, including securing each device connected to the network. This is accomplished by following and implementing all security guidance applicable for each node type. A fundamental step in securing each router is to enable only the capabilities required for operation.'
  desc  'rationale', ''
  desc  'check', "
    From the NSX Manager web interface, go to Networking >> Connectivity >> Tier-0 Gateways.

    For every Tier-0 Gateway, expand the Tier-0 Gateway, then expand Multicast to view the Multicast configuration.

    If Multicast is enabled and not in use, this is a finding.
  "
  desc 'fix', "
    To disable Multicast do the following:

    From the NSX Manager web interface, go to Networking >> Connectivity >> Tier-0 Gateways and edit the target Tier-0 Gateway.

    Expand Multicast, change from \"Enabled\" to \"Disabled\", and then click \"Save\".
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-NET-000131-RTR-000035'
  tag gid: 'V-VCFR-9X-000110'
  tag rid: 'SV-VCFR-9X-000110'
  tag stig_id: 'VCFR-9X-000110'
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
        t0id = t0['id']
        # Get locale-services id for T0
        t0lss = http("https://#{input('nsx_managerAddress')}/policy/api/v1/infra/tier-0s/#{t0id}/locale-services",
                     method: 'GET',
                     headers: {
                       'Accept' => 'application/json',
                       'X-XSRF-TOKEN' => "#{input('nsx_sessionToken')}",
                       'Cookie' => "#{input('nsx_sessionCookieId')}"
                     },
                     ssl_verify: false)

        t0lssjson = JSON.parse(t0lss.body)
        next unless t0lssjson['result_count'] != 0
        t0lssjson['results'].each do |t0ls|
          t0lsid = t0ls['id']
          # See if multicast is enabled on the T0 itself
          t0mc = http("https://#{input('nsx_managerAddress')}/policy/api/v1/infra/tier-0s/#{t0id}/locale-services/#{t0lsid}/multicast",
                      method: 'GET',
                      headers: {
                        'Accept' => 'application/json',
                        'X-XSRF-TOKEN' => "#{input('nsx_sessionToken')}",
                        'Cookie' => "#{input('nsx_sessionCookieId')}"
                      },
                      ssl_verify: false)

          t0mcjson = JSON.parse(t0mc.body)

          # 200 is returned if successful and multicast has ever been enabled on the T0 otherwise we get a 404 and can assume disabled
          if t0mc.status == 200
            # If multicast is enabled on the T0 it should be in the list so we can determine if any interfaces should have it enabled
            if t0mcjson['enabled']
              describe "T0 Gateway: #{t0['display_name']}" do
                subject { t0id }
                it { should be_in input('nsx_t0multicastlist') }
              end
              describe "T0 Gateway: #{t0['display_name']}. Multicast" do
                subject { t0mcjson }
                its(['enabled']) { should cmp 'true' }
              end
            # If multicast is not enabled on the T0 then no interfaces should have it enabled
            else
              describe "T0 Gateway: #{t0['display_name']}. Multicast" do
                subject { t0mcjson }
                its(['enabled']) { should cmp 'false' }
              end
            end
          # If 404 is returned then multicast has never been enabled on the T0 and all interfaces should not have it enabled
          else
            describe t0mc do
              its('status') { should cmp 404 }
            end
          end
        end
      end
    end
  end
end
