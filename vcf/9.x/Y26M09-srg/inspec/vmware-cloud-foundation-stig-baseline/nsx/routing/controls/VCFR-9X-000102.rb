control 'VCFR-9X-000102' do
  title 'The VMware Cloud Foundation NSX Tier-0 Gateway must be configured to advertise a hop limit of at least 32 in Router Advertisement messages for IPv6 stateless auto-configuration deployments.'
  desc  'The Neighbor Discovery protocol allows a hop limit value to be advertised by routers in a Router Advertisement message being used by hosts instead of the standardized default value. If a very small value was configured and advertised to hosts on the LAN segment, communications would fail due to the hop limit reaching zero before the packets sent by a host reached its destination.'
  desc  'rationale', ''
  desc  'check', "
    If IPv6 forwarding is not enabled, this is Not Applicable.

    From the NSX Manager web interface, go to Networking >> Connectivity >> Tier-0 Gateways.

    For every Tier-0 Gateway, expand Tier-0 Gateway >>Additional Settings.

    Click on the ND profile name to view the hop limit.

    If the hop limit is not configured to at least 32, this is a finding.
  "
  desc 'fix', "
    To configure the Neighbor Discovery hop limit do the following:

    From the NSX Manager web interface, go to Networking >> Connectivity >> Tier-0 Gateways >> edit the target Tier-0 gateway.

    Expand Additional Settings and select an \"ND Profile\" from the drop down with a hop limit of 32 or more, then click \"Close Editing\".

    Note: The default ND profile has a hop limit of 64 and cannot be edited. If required create a new or edit another existing ND profile to use.
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-NET-000512-RTR-000012'
  tag gid: 'V-VCFR-9X-000102'
  tag rid: 'SV-VCFR-9X-000102'
  tag stig_id: 'VCFR-9X-000102'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  result = http("https://#{input('nsx_managerAddress')}/policy/api/v1/infra/global-config",
                method: 'GET',
                headers: {
                  'Accept' => 'application/json',
                  'X-XSRF-TOKEN' => "#{input('nsx_sessionToken')}",
                  'Cookie' => "#{input('nsx_sessionCookieId')}"
                },
                ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    globalconf = JSON.parse(result.body)
    if globalconf['l3_forwarding_mode'] == 'IPV4_AND_IPV6'
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
            t0ndprofile = t0['ipv6_profile_paths'].find { |i| i.include?('ipv6-ndra-profiles') }
            ndprofile = http("https://#{input('nsx_managerAddress')}/policy/api/v1#{t0ndprofile}",
                             method: 'GET',
                             headers: {
                               'Accept' => 'application/json',
                               'X-XSRF-TOKEN' => "#{input('nsx_sessionToken')}",
                               'Cookie' => "#{input('nsx_sessionCookieId')}"
                             },
                             ssl_verify: false)

            describe ndprofile do
              its('status') { should cmp 200 }
            end
            next unless ndprofile.status == 200
            describe "T0 Gateway: #{t0['display_name']}. IPv6" do
              subject { json(content: ndprofile.body) }
              its(['ra_config', 'hop_limit']) { should cmp >= 32 }
            end
          end
        end
      end
    else
      impact 0.0
      describe 'IPv6 Forwarding is not enabled. This is Not Applicable.' do
        skip 'IPv6 Forwarding is not enabled. This is Not Applicable.'
      end
    end
  end
end
