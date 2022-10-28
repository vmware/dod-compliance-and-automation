control 'VCSA-70-000158' do
  title 'The vCenter Server must compare internal information system clocks at least every 24 hours with an authoritative time server.'
  desc  "
    Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside of the configured acceptable allowance (drift) may be inaccurate. Additionally, unnecessary synchronization may have an adverse impact on system performance and may indicate malicious activity.

    Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.
  "
  desc  'rationale', ''
  desc  'check', "
    Open the Virtual Appliance Management Interface (VAMI) by navigating to https://<vCenter server>:5480.

    Log in with local OS administrative credentials or with an SSO account that is a member of the \"SystemConfiguration.BashShellAdministrator\" group.

    Select \"Time\" on the left navigation pane.

    On the resulting pane on the right, ensure that at least one authorized time server is configured and is listed as \"Reachable\".

    If NTP is not enabled and at least one authorized time server configured, this is a finding.
  "
  desc 'fix', "
    Open the Virtual Appliance Management Interface (VAMI) by navigating to https://<vCenter server>:5480.

    Log in with local OS administrative credentials or with an SSO account that is a member of the \"SystemConfiguration.BashShellAdministrator\" group.

    Select \"Time\" on the left navigation pane.

    On the resulting pane on the right, click \"Edit\" under Time Synchronization.

    Select NTP for Mode and enter a list of authorized time servers separated by commas then click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000371'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCSA-70-000158'
  tag cci: ['CCI-001891']
  tag nist: ['AU-8 (1) (a)']

  # Check timesync mode
  result = http("https://#{input('vcURL')}/api/appliance/timesync",
              method: 'GET',
              headers: {
                'vmware-api-session-id' => "#{input('vcApiToken')}",
                },
              ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    describe result.body do
      it { should cmp '"NTP"' }
    end
  end

  # Check NTP Servers
  result = http("https://#{input('vcURL')}/api/appliance/ntp",
              method: 'GET',
              headers: {
                'vmware-api-session-id' => "#{input('vcApiToken')}",
                },
              ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    describe result.body do
      it { should_not cmp '[]' }
    end
    servers = JSON.parse(result.body)
    servers.each do |server|
      describe server do
        it { should be_in input('ntpServers') }
      end
    end
  end
  # Check status of ntp servers
  result = http("https://#{input('vcURL')}/api/appliance/ntp?action=test",
              method: 'POST',
              headers: {
                'vmware-api-session-id' => "#{input('vcApiToken')}",
                'Content-Type' => 'application/json',
                },
              data: { "servers": input('ntpServers') }.to_json,
              ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    describe result.body do
      it { should_not cmp '[]' }
    end
    servers = JSON.parse(result.body)
    servers.each do |server|
      describe server do
        its(['status']) { should cmp 'SERVER_REACHABLE' }
      end
    end
  end
end
