control 'NDFW-4X-000029' do
  title 'The NSX Distributed Firewall must configure Spoof Guard to restrict it from accepting outbound packets that contain an illegitimate address in the source address.'
  desc  "
    A compromised host in an enclave can be used by a malicious platform to launch cyberattacks on third parties. This is a common practice in \"botnets\", which are a collection of compromised computers using malware to attack other computers or networks. DDoS attacks frequently leverage IP source address spoofing to send packets to multiple hosts that in turn will then send return traffic to the hosts with the IP addresses that were forged. This can generate significant amounts of traffic. Therefore, protection measures to counteract IP source address spoofing must be taken.

    Spoof Guard is a tool that is designed to prevent virtual machines in your environment from sending traffic with an IP address from which it is not authorized to send traffic. In the instance that a virtual machine's IP address does not match the IP address on the corresponding logical port and segment address binding in Spoof Guard, the virtual machine's vNIC is prevented from accessing the network entirely. Spoof Guard can be configured at the port or segment level. There are several reasons Spoof Guard might be used in your environment, but for the distributed firewall it will guarantee that rules will not be inadvertently (or deliberately) bypassed. For DFW rules created utilizing IP sets as sources or destinations, the possibility always exists that a virtual machine could have its IP address forged in the packet header, thereby bypassing the rules in question.
  "
  desc  'rationale', ''
  desc  'check', "
    Identity Spoof Guard profiles in use by doing the following:

    From the NSX Manager web interface, go to Networking >> Connectivity >> Segments >> NSX.

    For each segment, expand view Segment Profiles >> Spoof Guard to note the profiles in use.

    Review Spoof Guard profile configuration by doing the following:

    From the NSX Manager web interface, go to Networking >> Connectivity >> Segments >> Profiles >> Segment Profiles.

    Review the Spoof Guard profiles previously identified as assigned to segments to ensure the following configuration:

    Port Bindings: Yes

    If a Segment is not configured with a Spoof Guard profile that has Port Bindings enabled, this is a finding.
  "
  desc 'fix', "
    To create a segment profile with Spoof Guard enabled, do the following:

    From the NSX Manager web interface, go to Networking >> Connectivity >> Segments >> Profiles >> Segment Profiles >> Add Segment Profile >> Spoof Guard.

    Enter a profile name and enable port bindings, then click \"Save\".

    To update a segments Spoof Guard profile, do the following:

    From the NSX Manager web interface, go to the Networking >> Connectivity >> Segments >> NSX, and click \"Edit\" from the drop-down menu next to the target segment.

    Expand \"Segment Profiles\" then choose the new Spoof Guard profile from the drop-down list, and then click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000364-FW-000042'
  tag gid: 'V-NDFW-4X-000029'
  tag rid: 'SV-NDFW-4X-000029'
  tag stig_id: 'NDFW-4X-000029'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  switches = http("https://#{input('nsxManager')}/api/v1/logical-switches",
                  method: 'GET',
                  headers: {
                    'Accept' => 'application/json',
                    'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                    'Cookie' => "#{input('sessionCookieId')}"
                  },
                  ssl_verify: false)

  describe switches do
    its('status') { should cmp 200 }
  end
  unless switches.status != 200
    swjson = JSON.parse(switches.body)
    if swjson['results'] == []
      describe 'No Segments/Logical Switches are deployed...skipping...' do
        skip 'No Segments/Logical Switches are deployed...skipping...'
      end
    else
      swjson['results'].each do |switch|
        switch['switching_profile_ids'].each do |swprofiles|
          next unless swprofiles['key'] == 'SpoofGuardSwitchingProfile'
          sgid = swprofiles['value']
          sgprofile = http("https://#{input('nsxManager')}/policy/api/v1/search?query=( resource_type:SpoofGuardProfile AND unique_id:#{sgid} )",
                           method: 'GET',
                           headers: {
                             'Accept' => 'application/json',
                             'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                             'Cookie' => "#{input('sessionCookieId')}"
                           },
                           ssl_verify: false)

          describe sgprofile do
            its('status') { should cmp 200 }
          end
          next unless sgprofile.status == 200
          sgpjson = JSON.parse(sgprofile.body)
          sgpjson['results'].each do |sgp|
            describe json(content: sgp.to_json) do
              its('address_binding_allowlist') { should cmp 'true' }
              its('address_binding_whitelist') { should cmp 'true' }
            end
          end
        end
      end
    end
  end
end
