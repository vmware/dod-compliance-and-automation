control 'NALB-CO-000074' do
  title 'The NSX Advanced Load Balancer Controller must authenticate Network Time Protocol sources using authentication that is cryptographically based.'
  desc  'If Network Time Protocol is not authenticated, an attacker can introduce a rogue NTP server. This rogue server can then be used to send incorrect time information to network devices, which will make log timestamps inaccurate and affect scheduled actions. NTP authentication is used to prevent this tampering by authenticating the time source.'
  desc  'rationale', ''
  desc  'check', "
    Review the network device configuration to determine if the network device authenticates NTP endpoints before establishing a local, remote, or network connection using authentication that is cryptographically based.

    From the NSX ALB Controller web interface go to Administration >> System Settings >> DNS/NTP.

    If the NSX ALB Controller is not configured to authenticate NTP sources, this is a finding.
  "
  desc 'fix', "
    From the NSX ALB Controller web interface go to Administration >> System Settings >> DNS/NTP.

    Click the edit icon next to \"System Settings\".

    Add or update an NTP server and provide the key number from the list of trusted keys to be used to authentication the time server and click Save.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000395-NDM-000347'
  tag gid: 'V-NALB-CO-000074'
  tag rid: 'SV-NALB-CO-000074'
  tag stig_id: 'NALB-CO-000074'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']

  results = http("https://#{input('avicontroller')}/api/systemconfiguration",
                  method: 'GET',
                  headers: {
                    'Accept-Encoding' => 'application/json',
                    'X-Avi-Version' => "#{input('aviversion')}",
                    'Cookie' => "sessionid=#{input('sessionCookieId')}",
                  },
                  ssl_verify: false)

  describe results do
    its('status') { should cmp 200 }
  end

  unless results.status != 200
    resultsjson = JSON.parse(results.body)
    if resultsjson['ntp_configuration']['ntp_servers'].empty?
      describe 'No NTP servers configured...skipping.' do
        skip 'No NTP servers configured...skipping.'
      end
    else
      resultsjson['ntp_configuration']['ntp_servers'].each do |ntpserver|
        describe "NTP Server: #{ntpserver['server']['addr']} authentication" do
          subject { ntpserver }
          its(['server', 'key_number']) { should_not be_nil }
        end
      end
    end
  end
end
