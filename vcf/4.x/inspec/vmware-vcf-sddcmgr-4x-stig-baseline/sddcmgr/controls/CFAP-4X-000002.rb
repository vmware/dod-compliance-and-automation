control 'CFAP-4X-000002' do
  title 'SDDC Manager components must use an authoritative time source.'
  desc  "
    Determining the correct time a particular application event occurred on a system is critical when conducting forensic analysis and investigating system events.

    Synchronization of system clocks is needed in order to correctly correlate the timing of events that occur across multiple systems. To meet this requirement, the organization will define an authoritative time source and have each system compare its internal clock at least every 24 hours.
  "
  desc  'rationale', ''
  desc  'check', "
    View the current NTP server configuration.

    From the SDDC Manager UI navigate to Administration >> Network Settings >> NTP Configuration and review the NTP servers listed.

    or

    From a command prompt, run the following command:

    $ curl 'https://sddc-manager.sfo01.rainpole.local/v1/system/ntp-configuration' -i -X GET -H 'Authorization: Bearer etYWRta....'

    Note: The SDDC manager URL and bearer token must be replaced in the example.

    If the NTP servers listed are not a site specific authoritative time source, this is a finding.
  "
  desc 'fix', "
    From the SDDC Manager UI navigate to Administration >> Network Settings >> NTP Configuration and click Edit.

    Review the information on updating NTP and click Next.

    Review the prerequisites and click Next.

    Enter new authoritative NTP servers in the text box and click Save.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000371-AS-000077'
  tag satisfies: ['SRG-APP-000372-AS-000212']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'CFAP-4X-000002'
  tag cci: ['CCI-001891', 'CCI-002046']
  tag nist: ['AU-8 (1) (a)', 'AU-8 (1) (b)']

  ntpServers = input('ntpServers')

  result = http("https://#{input('sddcManager')}/v1/system/ntp-configuration",
              method: 'GET',
              headers: {
                'Accept' => 'application/json',
                'Authorization' => "#{input('bearerToken')}",
                },
              ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    ntpresults = JSON.parse(result.body)
    ntpresults['ntpServers'].each do |ntp|
      describe json(content: ntp.to_json) do
        its('ipAddress') { should be_in ntpServers }
      end
    end
  end
end
