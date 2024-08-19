control 'NT0R-4X-000029' do
  title 'The NSX Tier-0 Gateway router must be configured to use encryption for Open Shortest Path First (OSPF) routing protocol authentication.'
  desc %q(A rogue router could send a fictitious routing update to convince a site's perimeter router to send traffic to an incorrect or even a rogue destination. This diverted traffic could be analyzed to learn confidential information about the site's network or used to disrupt the network's ability to communicate with other networks. This is known as a "traffic attraction attack" and is prevented by configuring neighbor router authentication for routing updates. However, using clear-text authentication provides little benefit since an attacker can intercept traffic and view the authentication key. This would allow the attacker to use the authentication key in an attack.

This requirement applies to all IPv4 and IPv6 protocols that are used to exchange routing or packet forwarding information; this includes all Interior Gateway Protocols (such as OSPF, Enhanced Interior Gateway Routing Protocol [EIGRP], and Intermediate System to Intermediate System [IS-IS]) and exterior gateway protocols (such as Border Gateway Protocol [BGP]), multiprotocol label switching (MPLS)-related protocols (such as Label Distribution Protocol [LDP]), and multicast-related protocols.

Typically routing protocols must be setup on both sides so knowing the authentication key does not necessarily mean an attacker would be able to setup a rogue router and peer with a legitimate one and inject malicious routes.)
  desc 'check', 'If the Tier-0 Gateway is not using OSPF, this is Not Applicable.

To verify OSPF areas are using authentication with encryption, do the following:

From the NSX Manager web interface, go to Networking >> Connectivity >> Tier-0 Gateways.

For every Tier-0 Gateway, expand the "Tier-0 Gateway".

Expand "OSPF", click the number next to "Area Definition", and view the "Authentication" field for each area.

If OSPF area definitions do not have the "Authentication" field set to "MD5" and a "Key ID" and "Password" configured, this is a finding.'
  desc 'fix', 'To set authentication for OSPF area definitions, do the following:

From the NSX Manager web interface, go to Networking >> Connectivity >> Tier-0 Gateways, and expand the target Tier-0 gateway.

Expand "OSPF", click the number next to "Area Definition". Select "Edit" on the target OSPF Area Definition.

Change the Authentication drop-down to MD5, enter a Key ID and Password, and then click "Save".

Note: The MD5 password can have a maximum of 16 characters.'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-NET-000168-RTR-000077'
  tag satisfies: ['SRG-NET-000230-RTR-000001']
  tag gid: 'V-263301'
  tag rid: 'SV-263301r977670_rule'
  tag stig_id: 'NT0R-4X-000029'
  tag cci: ['CCI-000366', 'CCI-000803']
  tag nist: ['CM-6 b', 'IA-7']

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
        t0id = t0['id']
        # Get locale-services id for T0
        t0lss = http("https://#{input('nsxManager')}/policy/api/v1/infra/tier-0s/#{t0id}/locale-services",
                     method: 'GET',
                     headers: {
                       'Accept' => 'application/json',
                       'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                       'Cookie' => "#{input('sessionCookieId')}"
                     },
                     ssl_verify: false)

        t0lssjson = JSON.parse(t0lss.body)
        next unless t0lssjson['result_count'] != 0
        t0lssjson['results'].each do |t0ls|
          t0lsid = t0ls['id']

          # Check for OSPF authentication
          # vrfs do not have OSPF configuration
          next unless t0['vrf_config'].nil?
          ospf = http("https://#{input('nsxManager')}/policy/api/v1/infra/tier-0s/#{t0id}/locale-services/#{t0lsid}/ospf",
                      method: 'GET',
                      headers: {
                        'Accept' => 'application/json',
                        'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                        'Cookie' => "#{input('sessionCookieId')}"
                      },
                      ssl_verify: false)

          describe ospf do
            its('status') { should cmp 200 }
          end
          next unless ospf.status == 200
          ospfjson = JSON.parse(ospf.body)
          if ospfjson['enabled']
            ospfareas = http("https://#{input('nsxManager')}/policy/api/v1/infra/tier-0s/#{t0id}/locale-services/#{t0lsid}/ospf/areas",
                             method: 'GET',
                             headers: {
                               'Accept' => 'application/json',
                               'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                               'Cookie' => "#{input('sessionCookieId')}"
                             },
                             ssl_verify: false)

            describe ospfareas do
              its('status') { should cmp 200 }
            end
            next unless ospfareas.status == 200
            ospfareasjson = JSON.parse(ospfareas.body)
            ospfareasjson['results'].each do |ospfarea|
              describe ospfarea do
                its(['authentication', 'mode']) { should be_in ['MD5'] }
              end
            end
          else
            describe "OSPF not enabled on T0: #{t0['display_name']}" do
              subject { ospfjson['enabled'] }
              it { should cmp 'false' }
            end
          end
        end
      end
    end
  end
end
