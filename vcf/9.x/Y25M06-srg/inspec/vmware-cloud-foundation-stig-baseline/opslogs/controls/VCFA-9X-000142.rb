control 'VCFA-9X-000142' do
  title 'VMware Cloud Foundation Operations for Logs must provide an immediate warning when allocated audit record storage volume reaches less than 30 days of maximum audit record storage capacity.'
  desc  'If security personnel are not notified immediately upon storage volume high utilization, they are unable to plan for storage capacity expansion.'
  desc  'rationale', ''
  desc  'check', "
    If VCF Operations for Logs is not deployed, this is not applicable.

    From VCF Operations for Logs, go to Configuration >> General.

    Review the \"Alerts\" configuration.

    If \"Retention Notification Threshold\" is not enabled and configured to 30 days or more, this is a finding.

    If \"Email System Notifications To\" and \"Send HTTP Post System Notifications To\" are empty, this is a finding.

    From VCF Operations for Logs, go to Alerts >> System Alerts.

    Review the \"Repository Retention Time\" Alert.

    If the \"Repository Retention Time\" Alert is not enabled, this is a finding.
  "
  desc 'fix', "
    From VCF Operations for Logs, go to Configuration >> General >> Alerts.

    Enable the \"Retention Notification Threshold\" and configure it to 30 days or 1 month.

    Configure either email notifications or HTTP Post notifications recipients to receive alerts and click Save.

    From VCF Operations for Logs, go to Alerts >> System Alerts.

    Ensure the \"Repository Retention Time\" Alert is enabled.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000359'
  tag gid: 'V-VCFA-9X-000142'
  tag rid: 'SV-VCFA-9X-000142'
  tag stig_id: 'VCFA-9X-000142'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']

  if input('opslogs_deployed')
    const_durations = {
      'MINUTES' => 0.00069,
      'HOURS' => 0.0417,
      'DAYS' => 1,
      'WEEKS' => 7.5,
      'MONTHS' => 30
    }.freeze

    response = http("https://#{input('opslogs_apihostname')}/api/v2/notification/config/retention-threshold",
                    method: 'GET',
                    ssl_verify: false,
                    headers: { 'Content-Type' => 'application/json',
                               'Accept' => 'application/json',
                               'Authorization' => "Bearer #{input('opslogs_apitoken')}" })

    describe 'REST API response for "retention-threshold"' do
      subject { response }
      its('status') { should cmp 200 }
    end

    unless response.status != 200
      responseval = json(content: response.body)

      if responseval
        time = responseval['dataInterval'].to_i * const_durations[responseval['intervalUnit']]

        describe 'Retention Notification Threshold' do
          subject { responseval }
          its(['sendNotification']) { should cmp true }
        end
        describe 'Retention Notification Threshold Minimum Duration in Days' do
          subject { time }
          it { should be >= 30 }
        end
      else
        describe 'Retention Notification Threshold' do
          subject { responseval }
          it { should_not be_nil }
        end
      end
    end

    systemalerts = http("https://#{input('opslogs_apihostname')}/api/v2/systemalerts",
                        method: 'GET',
                        ssl_verify: false,
                        headers: { 'Content-Type' => 'application/json',
                                   'Accept' => 'application/json',
                                   'Authorization' => "Bearer #{input('opslogs_apitoken')}" })

    describe 'REST API response for "systemalerts"' do
      subject { response }
      its('status') { should cmp 200 }
    end

    unless systemalerts.status != 200
      systemalertval = json(content: systemalerts.body).find { |item| item['alertName'] == 'Repository Retention Time' }

      describe 'Repository Retention Time' do
        subject { systemalertval }
        its(['enabled']) { should cmp true }
      end

      describe.one do
        describe 'Repository Retention Time Email Count' do
          subject { systemalertval['recipients']['emails'].length }
          it { should be >= 1 }
        end
        describe 'Repository Retention Time HTTP Post' do
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
