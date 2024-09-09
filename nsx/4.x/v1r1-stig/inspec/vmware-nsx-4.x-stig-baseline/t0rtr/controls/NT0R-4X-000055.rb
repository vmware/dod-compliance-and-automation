control 'NT0R-4X-000055' do
  title 'The NSX Tier-0 Gateway must be configured to use a unique password for each autonomous system (AS) with which it peers.'
  desc 'If the same keys are used between External Border Gateway Protocol (eBGP) neighbors, the chance of a hacker compromising any of the BGP sessions increases. It is possible that a malicious user exists in one autonomous system who would know the key used for the eBGP session. This user would then be able to hijack BGP sessions with other trusted neighbors.'
  desc 'check', '
    If the Tier-0 Gateway is not using BGP, this is Not Applicable.

    Since the NSX Tier-0 Gateway does not reveal the current password, interview the router administrator to determine if unique passwords are being used.

    If unique passwords are not being used for each AS, this is a finding.
  '
  desc 'fix', 'To set authentication for BGP neighbors, do the following:

From the NSX Manager web interface, go to Networking >> Connectivity >> Tier-0 Gateways, and expand the target Tier-0 gateway.

Expand BGP. Next to "BGP Neighbors", click on the number present to open the dialog, then select "Edit" on the target BGP Neighbor.

Expand "BGP", click the number next to "BGP Neighbors". Select "Edit" on the target BGP neighbor.

Under Timers & Password, enter a password up to 20 characters that is different from other autonomous systems, and then click "Save".'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000230-RTR-000002'
  tag gid: 'V-263304'
  tag rid: 'SV-263304r977679_rule'
  tag stig_id: 'NT0R-4X-000055'
  tag cci: ['CCI-002205']
  tag nist: ['AC-4 (17)']

  t0s = http("https://#{input('nsxManager')}/policy/api/v1/infra/tier-0s",
             method: 'GET',
             headers: {
               'Accept' => 'application/json',
               'X-XSRF-TOKEN' => "#{input('sessionToken')}",
               'Cookie' => "#{input('sessionCookieId')}"
             },
             ssl_verify: false)

  # if status is not 200 return a failure but if it's 200 do not run the test so this control does not pass and is properly skipped as a manual review.
  if t0s.status != 200
    describe t0s do
      its('status') { should cmp 200 }
    end
  else
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
          bgp = http("https://#{input('nsxManager')}/policy/api/v1/infra/tier-0s/#{t0id}/locale-services/#{t0lsid}/bgp",
                     method: 'GET',
                     headers: {
                       'Accept' => 'application/json',
                       'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                       'Cookie' => "#{input('sessionCookieId')}"
                     },
                     ssl_verify: false)

          next unless bgp.status == 200
          bgpjson = JSON.parse(bgp.body)
          if bgpjson['enabled']
            describe "Detected T0: #{t0['display_name']} with BGP enabled...manually verify unique keys are used per AS with neighbors" do
              skip "Detected T0: #{t0['display_name']} with BGP enabled...manually verify unique keys are used per AS with neighbors"
            end
          else
            describe "BGP not enabled on T0: #{t0['display_name']}" do
              subject { bgpjson['enabled'] }
              it { should cmp 'false' }
            end
          end
        end
      end
    end
  end
end
