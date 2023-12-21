control 'VLIA-8X-000002' do
  title 'VMware Aria Operations for Logs must be configured to synchronize time with an authoritative source.'
  desc  "
    If the application is not configured to collate records based on the time when the events occurred, the ability to perform forensic analysis and investigations across multiple components is significantly degraded. If the SIEM or other Central Log Server is out of sync with the host and devices for which it stores event logs, this may impact the accuracy of the records stored.

    Log records are time correlated if the time stamps in the individual log records can be reliably related to the time stamps in other log records to achieve a time ordering of the records within an organization-defined level of tolerance.

    This requirement applies only to applications that compile system-wide log records for multiple systems or system components.

    Note: The actual configuration and security requirements for NTP is handled in the host OS or NDM STIGs that are also required as part of a Central Log Server review.
  "
  desc  'rationale', ''
  desc  'check', "
    Login to VMware Aria Operations for Logs as an administrator.

    In the slide-out menu on the left, choose Configuration >> Time.

    If \"Sync Server Time With\" is not set to \"NTP Server (recommended)\", this is a finding.

    If \"NTP Servers (comma-separated)\" is not set to at least one valid DoD time source, this is a finding.
  "
  desc 'fix', "
    Login to VMware Aria Operations for Logs as an administrator.

    In the slide-out menu on the left, choose Configuration >> Time.

    Ensure \"Sync Server Time With\" is set to \"NTP Server (recommended)\".

    In the \"NTP Servers (comma-separated)\" field, supply at least one valid DoD time source.

    Click \"Save\".
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-APP-000086-AU-000030'
  tag gid: 'V-VLIA-8X-000002'
  tag rid: 'SV-VLIA-8X-000002'
  tag stig_id: 'VLIA-8X-000002'
  tag cci: ['CCI-000174']
  tag nist: ['AU-12 (1)']

  token = http("https://#{input('apipath')}/sessions",
    method: 'POST',
    headers: {
    'Content-Type' => 'application/json',
    'Accept' => 'application/json',
    },
    data: "{\"username\":\"#{input('username')}\",\"password\":\"#{input('password')}\",\"provider\":\"Local\"}",
    ssl_verify: false)

  describe token do
    its('status') { should cmp 200 }
  end

  unless token.status != 200
    sessID = JSON.parse(token.body)['sessionId']

    response = http("https://#{input('apipath')}/time/config",
      method: 'GET',
      headers: {
      'Content-Type' => 'application/json',
      'Accept' => 'application/json',
      'Authorization' => "Bearer #{sessID}",
      },
      ssl_verify: false)

    describe response do
      its('status') { should cmp 200 }
    end

    unless response.status != 200
      result = JSON.parse(response.body)
      allowed = input('ntpServers')

      describe result['ntpConfig'] do
        its(['timeReference']) { should cmp 'NTP_SERVER' }
      end

      result['ntpConfig']['ntpServers'].each do |item|
        describe item do
          it { should be_in allowed }
        end
      end
    end
  end
end
