control 'NDFW-4X-000029' do
  title 'The NSX Distributed Firewall must configure Spoof Guard to restrict it from accepting outbound packets that contain an illegitimate address in the source address.'
  desc %q(A compromised host in an enclave can be used by a malicious platform to launch cyberattacks on third parties. This is a common practice in "botnets", which are a collection of compromised computers using malware to attack other computers or networks. Distributed denial-of-service (DDoS) attacks frequently leverage IP source address spoofing to send packets to multiple hosts that in turn will then send return traffic to the hosts with the IP addresses that were forged. This can generate significant amounts of traffic. Therefore, protection measures to counteract IP source address spoofing must be taken.

SpoofGuard is a tool that is designed to prevent virtual machines from sending traffic with an IP address from which it is not authorized to send traffic. In the instance that a virtual machine's IP address does not match the IP address on the corresponding logical port and segment address binding in SpoofGuard, the virtual machine's virtual network interface card (vNIC) is prevented from accessing the network entirely. SpoofGuard can be configured at the port or segment level. There are several reasons SpoofGuard might be used, but for the distributed firewall it will guarantee that rules will not be inadvertently (or deliberately) bypassed. For distributed firewall (DFW) rules created using IP sets as sources or destinations, the possibility always exists that a virtual machine could have its IP address forged in the packet header, thereby bypassing the rules in question.)
  desc 'check', 'Identity SpoofGuard profiles in use by doing the following:

From the NSX Manager web interface, navigate to Networking >> Connectivity >> Segments >> NSX.

For each segment, expand view Segment Profiles >> SpoofGuard to note the profiles in use.

Review SpoofGuard profile configuration by doing the following:

From the NSX Manager web interface, navigate to Networking >> Connectivity >> Segments >> Profiles >> Segment Profiles.

Review the SpoofGuard profiles previously identified as assigned to segments to ensure the following configuration:

Port Bindings: Yes

If a segment is not configured with a SpoofGuard profile that has port bindings enabled, this is a finding.'
  desc 'fix', 'To create a segment profile with SpoofGuard enabled, do the following:

From the NSX Manager web interface, navigate to Networking >> Connectivity >> Segments >> Profiles >> Segment Profiles >> Add Segment Profile >> SpoofGuard.

Enter a profile name and enable port bindings, then click "Save".

To update a segments SpoofGuard profile, do the following:

From the NSX Manager web interface, navigate to the Networking >> Connectivity >> Segments >> NSX, and click "Edit" from the drop-down menu next to the target segment.

Expand "Segment Profiles" then choose the new SpoofGuard profile from the drop-down list, and then click "Save".'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000364-FW-000042'
  tag gid: 'V-263181'
  tag rid: 'SV-263181r977310_rule'
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
