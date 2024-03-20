control 'NDFW-4X-000034' do
  title 'The NSX Distributed Firewall must configure an IP Discovery profile to disable trust on every use methods.'
  desc  "
    A compromised host in an enclave can be used by a malicious platform to launch cyberattacks on third parties. This is a common practice in \"botnets\", which are a collection of compromised computers using malware to attack other computers or networks. DDoS attacks frequently leverage IP source address spoofing to send packets to multiple hosts that in turn will then send return traffic to the hosts with the IP addresses that were forged. This can generate significant amounts of traffic. Therefore, protection measures to counteract IP source address spoofing must be taken.

    IP Discovery in NSX uses DHCP and DHCPv6 snooping, ARP (Address Resolution Protocol) snooping, ND (Neighbor Discovery) snooping, and VM Tools to learn MAC and IP addresses.

    The discovered MAC and IP addresses are used to achieve ARP/ND suppression, which minimizes traffic between VMs connected to the same logical switch. The addresses are also used by the SpoofGuard and distributed firewall (DFW) components. DFW uses the address bindings to determine the IP address of objects in firewall rules.

    By default, the discovery methods ARP snooping and ND snooping operate in a mode called trust on first use (TOFU). In TOFU mode, when an address is discovered and added to the realized bindings list, that binding remains in the realized list forever. TOFU applies to the first 'n' unique <IP, MAC, VLAN> bindings discovered using ARP/ND snooping, where 'n' is the binding limit that you can configure. You can disable TOFU for ARP/ND snooping. The methods will then operate in trust on every use (TOEU) mode. In TOEU mode, when an address is discovered, it is added to the realized bindings list and when it is deleted or expired, it is removed from the realized bindings list. DHCP snooping and VM Tools always operate in TOEU mode
  "
  desc  'rationale', ''
  desc  'check', "
    From the NSX Manager web interface, go to Networking >> Connectivity >> Segments, and for each Segment, view Segment Profiles >> IP Discovery.

    Review the IP Discovery profile to ensure the following configuration:

    Duplicate IP Detection: Enabled
    ARP Snooping: Enabled
    ARP Binding Limit: 1
    DHCP Snooping: Disabled
    DHCP Snooping - IPv6: Disabled
    VMware Tools: Disabled
    VMware Tools - IPv6: Disabled
    Trust on First Use: Enabled

    If a Segment is not configured with an IP Discovery profile that is configured with the settings above, this is a finding.
  "
  desc 'fix', "
    To create a segment profile for IP Discovery, do the following:

    From the NSX Manager web interface, go to Networking >> Connectivity >> Segments >> Segment Profiles >> Add Segment Profile >> IP Discovery.

    Enter a profile name then configure the below settings

    Duplicate IP Detection: Enabled
    ARP Snooping: Enabled
    ARP Binding Limit: 1
    DHCP Snooping: Disabled
    DHCP Snooping - IPv6: Disabled
    VMware Tools: Disabled
    VMware Tools - IPv6: Disabled
    Trust on First Use: Enabled

    Click \"Save\".

    Note: ND Snooping may be enabled if IPv6 is in use.

    To update a Segments IP Discovery profile, do the following:

    From the NSX Manager web interface, go to the Networking >> Segments, and click \"Edit\" from the drop-down menu next to the target Segment.

    Expand \"Segment Profiles\" then choose the new IP Discovery profile from the drop-down list, and then click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000364-FW-000042'
  tag gid: 'V-NDFW-4X-000034'
  tag rid: 'SV-NDFW-4X-000034'
  tag stig_id: 'NDFW-4X-000034'
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
          next unless swprofiles['key'] == 'IpDiscoverySwitchingProfile'
          ipid = swprofiles['value']
          ipprofile = http("https://#{input('nsxManager')}/policy/api/v1/search?query=( resource_type:IPDiscoveryProfile AND unique_id:#{ipid} )",
                           method: 'GET',
                           headers: {
                             'Accept' => 'application/json',
                             'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                             'Cookie' => "#{input('sessionCookieId')}"
                           },
                           ssl_verify: false)

          describe ipprofile do
            its('status') { should cmp 200 }
          end
          next unless ipprofile.status == 200
          ippjson = JSON.parse(ipprofile.body)
          ippjson['results'].each do |ipp|
            describe json(content: ipp.to_json) do
              its('tofu_enabled') { should cmp 'true' }
              its(['ip_v4_discovery_options', 'arp_snooping_config', 'arp_snooping_enabled']) { should cmp 'true' }
              its(['ip_v4_discovery_options', 'arp_snooping_config', 'arp_binding_limit']) { should cmp '1' }
              its(['ip_v4_discovery_options', 'dhcp_snooping_enabled']) { should cmp 'false' }
              its(['ip_v4_discovery_options', 'vmtools_enabled']) { should cmp 'false' }
              its(['ip_v6_discovery_options', 'dhcp_snooping_v6_enabled']) { should cmp 'false' }
              its(['ip_v6_discovery_options', 'vmtools_v6_enabled']) { should cmp 'false' }
            end
          end
        end
      end
    end
  end
end
