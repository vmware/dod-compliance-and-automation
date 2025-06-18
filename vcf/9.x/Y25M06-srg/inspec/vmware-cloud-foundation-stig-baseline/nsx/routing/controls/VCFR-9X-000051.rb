control 'VCFR-9X-000051' do
  title 'The VMware Cloud Foundation NSX Tier-0 Gateway must be configured to restrict it from accepting outbound IP packets that contain an illegitimate address in the source address field by enabling Unicast Reverse Path Forwarding (uRPF).'
  desc  'A compromised host in an enclave can be used by a malicious platform to launch cyber attacks on third parties. This is a common practice in "botnets", which are a collection of compromised computers using malware to attack other computers or networks. DDoS attacks frequently leverage IP source address spoofing to send packets to multiple hosts that in turn will then send return traffic to the hosts with the IP addresses that were forged. This can generate significant amounts of traffic. Therefore, protection measures to counteract IP source address spoofing must be taken. When uRPF is enabled in strict mode, the packet must be received on the interface that the device would use to forward the return packet; thereby mitigating IP source address spoofing.'
  desc  'rationale', ''
  desc  'check', "
    From the NSX Manager web interface, go to Networking >> Connectivity >> Tier-0 Gateways.

    For every Tier-0 Gateway, expand Tier-0 Gateway >> Interfaces and GRE Tunnels, and then click on the number of interfaces present to open the interfaces dialog.

    Expand each interface to view the URPF Mode configuration.

    If URPF Mode is not set to \"Strict\" on any interface, this is a finding.
  "
  desc 'fix', "
    Enable strict URPF mode on interfaces by doing the following:

    From the NSX Manager web interface, go to Networking >> Connectivity >> Tier-0 Gateways and expand the target Tier-0 gateway.

    Expand \"Interfaces and GRE Tunnels\", click on the number of interfaces present to open the interfaces dialog, and then select \"Edit\" on the target interface.

    From the drop-down, set the URPF mode to \"Strict\" and then click \"Save\".
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-NET-000205-RTR-000014'
  tag gid: 'V-VCFR-9X-000051'
  tag rid: 'SV-VCFR-9X-000051'
  tag stig_id: 'VCFR-9X-000051'
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']

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
          # Get all T0 interfaces
          t0ints = http("https://#{input('nsx_managerAddress')}/policy/api/v1/infra/tier-0s/#{t0id}/locale-services/#{t0lsid}/interfaces",
                        method: 'GET',
                        headers: {
                          'Accept' => 'application/json',
                          'X-XSRF-TOKEN' => "#{input('nsx_sessionToken')}",
                          'Cookie' => "#{input('nsx_sessionCookieId')}"
                        },
                        ssl_verify: false)

          describe t0ints do
            its('status') { should cmp 200 }
          end
          next unless t0ints.status == 200
          t0intsjson = JSON.parse(t0ints.body)
          t0intsjson['results'].each do |int|
            describe "T0 Gateway: #{t0['display_name']} with interface id: #{int['id']}" do
              subject { int }
              its(['urpf_mode']) { should cmp 'STRICT' }
            end
          end
        end
      end
    end
  end
end
