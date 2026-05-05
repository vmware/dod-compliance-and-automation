control 'VCFA-9X-000143' do
  title 'VMware Cloud Foundation Operations for Logs must provide an immediate real-time alert when inactive hosts are detected.'
  desc  "
    It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected.

    Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less).
  "
  desc  'rationale', ''
  desc  'check', "
    If VCF Operations for Logs is not deployed, this is not applicable.

    From VCF Operations for Logs, go to Management >> Hosts.

    Review the \"Inactive hosts notification\" configuration.

    If \"Inactive hosts notification\" is not enabled, this is a finding.

    If \"Inactive hosts notification acceptlist\" is enabled, this is a finding.
  "
  desc 'fix', "
    From VCF Operations for Logs, go to Configuration >> Management >> Hosts.

    Enable the \"Inactive hosts notification\" and configure a time period to receive alerts after the last event.

    If the \"Inactive hosts notification acceptlist\" is enabled, disable it and click Save.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000360'
  tag gid: 'V-VCFA-9X-000143'
  tag rid: 'SV-VCFA-9X-000143'
  tag stig_id: 'VCFA-9X-000143'
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']

  if input('opslogs_deployed')
    describe 'The "Inactive hosts notification acceptlist" check is manual either due to no available API or is policy based and must be reviewed manually.' do
      skip 'The "Inactive hosts notification acceptlist" check is manual either due to no available API or is policy based and must be reviewed manually.'
    end

    systemalerts = http("https://#{input('opslogs_apihostname')}/api/v2/systemalerts",
                        method: 'GET',
                        ssl_verify: false,
                        headers: { 'Content-Type' => 'application/json',
                                   'Accept' => 'application/json',
                                   'Authorization' => "Bearer #{input('opslogs_apitoken')}" })

    describe 'REST API response' do
      subject { systemalerts }
      its('status') { should cmp 200 }
    end

    unless systemalerts.status != 200
      systemalertval = json(content: systemalerts.body).find { |item| item['alertName'] == 'Inactive Host Alert' }

      describe 'Inactive Host Alert' do
        subject { systemalertval }
        its(['enabled']) { should cmp true }
      end

      describe.one do
        describe 'Inactive Host Alert Email Count' do
          subject { systemalertval['recipients']['emails'].length }
          it { should be >= 1 }
        end
        describe 'Inactive Host Alert HTTP Post' do
          subject { systemalertval['recipients']['webhooks'] }
          it { should_not cmp '' }
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
