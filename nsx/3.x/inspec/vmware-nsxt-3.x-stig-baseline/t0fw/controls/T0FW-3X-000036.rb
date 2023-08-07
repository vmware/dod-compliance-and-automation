control 'T0FW-3X-000036' do
  title 'The NSX-T Tier-0 Gateway Firewall must configure SpoofGuard to block outbound IP packets that contain illegitimate packet attributes.'
  desc 'If outbound communications traffic is not filtered, hostile activity intended to harm other networks may not be detected and prevented.'
  desc 'check', 'From the NSX-T Manager web interface, go to Networking >> Segments and for each Segment, view Segment Profiles >> SpoofGuard.

If a Segment is not configured with a SpoofGuard profile that has Port Binding enabled, this is a finding.'
  desc 'fix', 'To create a segment profile with SpoofGuard enabled, do the following:

From the NSX-T Manager web interface, go to Networking >> Segments >> Segment Profiles >> Add Segment Profile >> SpoofGuard.

Enter a profile name, enable port bindings, and then click "Save".

To update a Segments SpoofGuard profile, do the following:

From the NSX-T Manager web interface, go to Networking >> Segments and click "Edit" from the drop-down menu next to the target Segment.

Expand Segment Profiles, choose the new SpoofGuard profile from the drop-down list, and then click "Save".'
  impact 0.5
  tag check_id: 'C-55180r810094_chk'
  tag severity: 'medium'
  tag gid: 'V-251743'
  tag rid: 'SV-251743r810096_rule'
  tag stig_id: 'T0FW-3X-000036'
  tag gtitle: 'SRG-NET-000364-FW-000042'
  tag fix_id: 'F-55134r810095_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  switches = http("https://#{input('nsxManager')}/api/v1/logical-switches",
              method: 'GET',
              headers: {
                'Accept' => 'application/json',
                'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                'Cookie' => "#{input('sessionCookieId')}",
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
                'Cookie' => "#{input('sessionCookieId')}",
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
