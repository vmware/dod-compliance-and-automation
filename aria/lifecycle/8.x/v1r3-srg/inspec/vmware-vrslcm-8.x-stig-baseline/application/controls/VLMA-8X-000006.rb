control 'VLMA-8X-000006' do
  title 'VMware Aria Suite Lifecycle must synchronize server clocks with an authoritative time source.'
  desc  "
    Determining the correct time a particular application event occurred on a system is critical when conducting forensic analysis and investigating system events.

    Synchronization of internal application server clocks is needed in order to correctly correlate the timing of events that occur across multiple systems.
  "
  desc  'rationale', ''
  desc  'check', "
    Login to VMware Aria Suite Lifecycle as the admin@local account.

    Select \"Lifecycle Operations\" >> Settings >> System Administration >> Time Settings to view the configuration.

    If NTP is not used to synchronize time, this is a finding.

    If the NTP servers specified are not authoritative for the organization, this is a finding.
  "
  desc 'fix', "
    Configure an authoritative NTP Server on VMware vRealize Suite Lifecycle.

    Login to VMware Aria Suite Lifecycle as the admin@local account.

    Select \"Lifecycle Operations\" >> Settings >> System Administration >> Time Settings.

    If NTP is not configured select the \"Use Time Server (NTP)\" option and configure one or more authoritative time sources.

    If the NTP servers specified are not authoritative update them to an authorized time server.

    Click Save.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000371-AS-000077'
  tag satisfies: ['SRG-APP-000372-AS-000212']
  tag gid: 'V-VLMA-8X-000006'
  tag rid: 'SV-VLMA-8X-000006'
  tag stig_id: 'VLMA-8X-000006'
  tag cci: ['CCI-001891', 'CCI-002046']
  tag nist: ['AU-8 (1) (a)', 'AU-8 (1) (b)']

  cred = Base64.encode64("#{input('username')}:#{input('password')}")

  response = http("https://#{input('hostname')}/lcm/lcops/api/v2/settings/system-details/time",
                  method: 'GET',
                  headers: {
                    'Content-Type' => 'application/json',
                    'Accept' => 'application/json',
                    'Authorization' => "Basic #{cred}"
                  },
                  ssl_verify: false)

  describe response do
    its('status') { should cmp 200 }
  end

  unless response.status != 200
    result = JSON.parse(response.body)

    describe result['ntpServerEnabled'] do
      it { should cmp true }
    end

    describe result['ntpServerStarted'] do
      it { should cmp true }
    end

    input('ntpServers').each do |ntp|
      describe result['ntpServers'] do
        it { should include ntp }
      end
    end
  end
end
