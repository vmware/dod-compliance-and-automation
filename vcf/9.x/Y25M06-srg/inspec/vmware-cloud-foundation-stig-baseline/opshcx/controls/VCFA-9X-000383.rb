control 'VCFA-9X-000383' do
  title 'VMware Cloud Foundation Operations HCX must compare internal information system clocks with an authoritative time server.'
  desc  "
    Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside of the configured acceptable allowance (drift) may be inaccurate. Additionally, unnecessary synchronization may have an adverse impact on system performance and may indicate malicious activity.

    Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network. Organizations must consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints).
  "
  desc  'rationale', ''
  desc  'check', "
    If VCF Operations HCX is not deployed, this is not applicable.

    From the VCF Operations HCX Administration interface, go to Administration >> General Settings >> Time Settings.

    Review the NTP server configuration.

    If the NTP servers listed are not site specific authoritative time sources, this is a finding.
  "
  desc 'fix', "
    From the VCF Operations HCX Administration interface, go to Administration >> General Settings >> Time Settings.

    Click \"Edit\".

    Enter a list of authorized time servers separated by commas into the \"NTP Server\" field and click \"Save\".

    Editing NTP Settings requires restarting the Appliance Management Service. This service can be restarted from the Appliance Summary tab.

    Note: It is recommended to configure 1 or 3 or more NTP servers to help prevent \"split-brain\" scenarios.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000371'
  tag gid: 'V-VCFA-9X-000383'
  tag rid: 'SV-VCFA-9X-000383'
  tag stig_id: 'VCFA-9X-000383'
  tag cci: ['CCI-004923']
  tag nist: ['SC-45 (1) (a)']

  if input('opshcx_deployed')
    result = http("https://#{input('opshcx_url')}:9443/system/timesettings",
                  method: 'GET',
                  headers: {
                    'Authorization' => "Basic #{input('opshcx_apiToken')}"
                  },
                  ssl_verify: false)

    describe result do
      its('status') { should cmp 200 }
    end
    unless result.status != 200
      resultjson = JSON.parse(result.body)

      if resultjson['ntpServer'].blank?
        describe 'No NTP servers found. Configured NTP servers' do
          subject { resultjson['ntpServer'] }
          it { should_not be_blank }
        end
      else
        # Compare results coming from server to allowed input list
        resultjson['ntpServer'].each do |ntpserver|
          describe "Configured NTP server: #{ntpserver}" do
            subject { ntpserver }
            it { should be_in input('opshcx_ntpServers') }
          end
        end
        # Compare allowed input list to server configuration, ensure each is there
        input('opshcx_ntpServers').each do |ntp|
          describe "Allowed NTP server: #{ntp}" do
            subject { ntp }
            it { should be_in resultjson['ntpServer'] }
          end
        end
      end
    end
  else
    impact 0.0
    describe 'VCF Operations HCX is not deployed in the target environment. This control is N/A.' do
      skip 'VCF Operations HCX is not deployed in the target environment. This control is N/A.'
    end
  end
end
