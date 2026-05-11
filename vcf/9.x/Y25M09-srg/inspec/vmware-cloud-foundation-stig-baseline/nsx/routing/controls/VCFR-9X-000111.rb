control 'VCFR-9X-000111' do
  title 'The VMware Cloud Foundation NSX Tier-0 Gateway router must be configured to use encryption for BGP routing protocol authentication.'
  desc  "
    A rogue router could send a fictitious routing update to convince a site's perimeter router to send traffic to an incorrect or even a rogue destination. This diverted traffic could be analyzed to learn confidential information about the site's network or used to disrupt the network's ability to communicate with other networks. This is known as a \"traffic attraction attack\" and is prevented by configuring neighbor router authentication for routing updates. However, using clear-text authentication provides little benefit since an attacker can intercept traffic and view the authentication key. This would allow the attacker to use the authentication key in an attack.

    This requirement applies to all IPv4 and IPv6 protocols that are used to exchange routing or packet forwarding information; this includes all Interior Gateway Protocols (such as OSPF, EIGRP, and IS-IS) and Exterior Gateway Protocols (such as BGP), MPLS-related protocols (such as LDP), and multicast-related protocols.
  "
  desc  'rationale', ''
  desc  'check', "
    If the Tier-0 Gateway is not using BGP, this is Not Applicable.

    To verify BGP neighbors are using authentication with encryption do the following:

    From the NSX Manager web interface, go to Networking >> Connectivity >> Tier-0 Gateways.

    For every Tier-0 Gateway expand the \"Tier-0 Gateway\".

    Expand \"BGP\", click the number next to \"BGP Neighbors\" and expand each BGP neighbor.

    Expand the \"Timers and Password\" section and review the Password field.

    If any BGP neighbors do not have a password configured, this is a finding.
  "
  desc 'fix', "
    To set authentication for BGP neighbors do the following:

    From the NSX Manager web interface, go to Networking >> Connectivity >> Tier-0 Gateways, and expand the target Tier-0 gateway.

    Expand BGP. Next to BGP Neighbors, click on the number present to open the dialog, then select \"Edit\" on the target BGP Neighbor.

    Expand \"BGP\", click the number next to \"BGP Neighbors\". Select \"Edit\" on the target BGP neighbor.

    Under Timers & Password, enter a password up to 20 characters, and then click \"Save\".
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-NET-000168-RTR-000077'
  tag gid: 'V-VCFR-9X-000111'
  tag rid: 'SV-VCFR-9X-000111'
  tag stig_id: 'VCFR-9X-000111'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']

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
          # Check for BGP Neighbor passwords
          bgp = http("https://#{input('nsx_managerAddress')}/policy/api/v1/infra/tier-0s/#{t0id}/locale-services/#{t0lsid}/bgp",
                     method: 'GET',
                     headers: {
                       'Accept' => 'application/json',
                       'X-XSRF-TOKEN' => "#{input('nsx_sessionToken')}",
                       'Cookie' => "#{input('nsx_sessionCookieId')}"
                     },
                     ssl_verify: false)

          describe bgp do
            its('status') { should cmp 200 }
          end
          next unless bgp.status == 200
          bgpjson = JSON.parse(bgp.body)
          if bgpjson['enabled']
            bgpnbrs = http("https://#{input('nsx_managerAddress')}/policy/api/v1/infra/tier-0s/#{t0id}/locale-services/#{t0lsid}/bgp/neighbors",
                           method: 'GET',
                           headers: {
                             'Accept' => 'application/json',
                             'X-XSRF-TOKEN' => "#{input('nsx_sessionToken')}",
                             'Cookie' => "#{input('nsx_sessionCookieId')}"
                           },
                           ssl_verify: false)

            describe bgpnbrs do
              its('status') { should cmp 200 }
            end
            next unless bgpnbrs.status == 200
            bgpnbrsjson = JSON.parse(bgpnbrs.body)
            if bgpnbrsjson['result_count'] != 0
              bgpnbrsjson['results'].each do |bgpnbr|
                describe "T0 Gateway: #{t0['display_name']}. BGP Neighbor" do
                  subject { bgpnbr }
                  its(['password_set']) { should cmp 'true' }
                end
              end
            else
              describe "No BGP Neighbors found on T0 Gateway: #{t0['display_name']}. BGP Neighbors" do
                subject { bgpnbrsjson }
                its(['result_count']) { should cmp 0 }
              end
            end
          else
            describe "T0 Gateway: #{t0['display_name']} BGP" do
              subject { bgpjson }
              its(['enabled']) { should cmp 'false' }
            end
          end
        end
      end
    end
  end
end
