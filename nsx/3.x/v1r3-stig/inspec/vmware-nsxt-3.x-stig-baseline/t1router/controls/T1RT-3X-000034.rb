control 'T1RT-3X-000034' do
  title 'The NSX-T Tier-1 Gateway must be configured to enforce a Quality-of-Service (QoS) policy to limit the effects of packet flooding denial-of-service (DoS) attacks.'
  desc 'DoS is a condition when a resource is not available for legitimate users. Packet flooding distributed denial-of-service (DDoS) attacks are referred to as volumetric attacks and have the objective of overloading a network or circuit to deny or seriously degrade performance, which denies access to the services that normally traverse the network or circuit. Volumetric attacks have become relatively easy to launch using readily available tools such as Low Orbit Ion Cannon or botnets.

Measures to mitigate the effects of a successful volumetric attack must be taken to ensure that sufficient capacity is available for mission-critical traffic. Managing capacity may include, for example, establishing selected network usage priorities or quotas and enforcing them using rate limiting, Quality of Service (QoS), or other resource reservation control methods. These measures may also mitigate the effects of sudden decreases in network capacity that are the result of accidental or intentional physical damage to telecommunications facilities (such as cable cuts or weather-related outages).'
  desc 'check', 'From the NSX-T Manager web interface, go to Networking >> Segments.

For every Segment connected to a Tier-1 Gateway, Expand Segment >> Expand Segment Profiles >> Record QOS Segment Profile.

Go to Segment Profiles >> Expand QOS Segment Profile recorded in previous steps.

If there are traffic priorities specified by the Combatant Commands/Services/Agencies needed to ensure sufficient capacity for mission-critical traffic and none are configured, this is a finding.'
  desc 'fix', 'To create a segment QoS profile, do the following:

From the NSX-T Manager web interface, go to Networking >> Segments >> Segment Profiles.

Click "Add Segment Profile" and select "QoS".

Configure a profile name and QoS settings as needed and click "Save".

To apply a QoS profile to a segment do the following:

From the NSX-T Manager web interface, go to Networking >> Segments and edit the target segment.

Expand Segment Profiles and under QoS select the profile previously created and "Save".'
  impact 0.5
  tag check_id: 'C-55209r810214_chk'
  tag severity: 'medium'
  tag gid: 'V-251772'
  tag rid: 'SV-251772r810216_rule'
  tag stig_id: 'T1RT-3X-000034'
  tag gtitle: 'SRG-NET-000193-RTR-000112'
  tag fix_id: 'F-55163r810215_fix'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']

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
      describe 'No T1 Gateways are deployed...skipping...' do
        skip 'No T1 Gateways are deployed...skipping...'
      end
    else
      describe 'This check is a manual check' do
        skip 'This is a manual check. Review that QoS policies support traffic priorities specified by the Combatant Commands/Services/Agencies needed to ensure sufficient capacity for mission-critical traffic.'
      end
    end
  end
end
