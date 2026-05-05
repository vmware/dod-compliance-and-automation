control 'VCFA-9X-000367' do
  title 'VMware Cloud Foundation Operations must configure Operations for Logs to compare internal information system clocks with an authoritative time server.'
  desc  "
    Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside of the configured acceptable allowance (drift) may be inaccurate. Additionally, unnecessary synchronization may have an adverse impact on system performance and may indicate malicious activity.

    Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network. Organizations must consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints).
  "
  desc  'rationale', ''
  desc  'check', "
    If VCF Operations for Logs is not deployed, this is not applicable.

    From VCF Operations, go to Fleet Management >> Lifecycle >> VCF Management >> Overview.

    Click \"Manage\" on the operations-logs capability and view the currently configured NTP servers.

    Verify at least one authorized time server is configured.

    If the NTP servers listed are not site specific authoritative time sources, this is a finding.
  "
  desc 'fix', "
    From VCF Operations, go to Fleet Management >> Lifecycle >> VCF Management >> Overview.

    Click \"Manage\" on the operations-logs capability.

    Click \"Update NTP Configuration\" and click \"Proceed\".

    Review the current NTP configuration and click \"Next\".

    Select \"Use NTP server\" and add or select existing authoritative time servers from the list and click \"Next\".

    Update the server priority as needed and click \"Next\".

    Click \"Run Precheck\" to verify connectivity to the selected NTP servers and click \"Finish\" to complete the configuration.

    Note: It is recommended to configure 1 or 3 or more NTP servers to help prevent \"split-brain\" scenarios.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000371'
  tag gid: 'V-VCFA-9X-000367'
  tag rid: 'SV-VCFA-9X-000367'
  tag stig_id: 'VCFA-9X-000367'
  tag cci: ['CCI-004923']
  tag nist: ['SC-45 (1) (a)']

  if input('opslogs_deployed')
    response = http("https://#{input('opslogs_apihostname')}/api/v2/time/config",
                    method: 'GET',
                    ssl_verify: false,
                    headers: { 'Content-Type' => 'application/json',
                               'Accept' => 'application/json',
                               'Authorization' => "Bearer #{input('opslogs_apitoken')}" })

    describe response do
      its('status') { should cmp 200 }
    end

    unless response.status != 200
      responseval = json(content: response.body)['ntpConfig']

      if responseval
        describe 'NTP time source must be enabled' do
          subject { responseval['timeReference'] }
          it { should cmp 'NTP_SERVER' }
        end
        responseval['ntpServers'].each do |ntpserver|
          describe "NTP time server '#{ntpserver}'" do
            subject { ntpserver }
            it { should be_in input('opslogs_ntpServers') }
          end
        end
      else
        describe 'NTP time source must be enabled' do
          subject { responseval }
          it { should_not be_nil }
        end
      end
    end
  else
    impact 0.0
    describe 'VCF Operations for Logs is not deployed in the target environment. This control is N/A.' do
      skip 'VCF Operations for Logs is not deployed in the target environment. This control is N/A.'
    end
  end
end
