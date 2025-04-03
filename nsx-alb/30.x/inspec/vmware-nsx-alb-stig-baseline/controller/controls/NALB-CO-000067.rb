control 'NALB-CO-000067' do
  title 'The NSX Advanced Load Balancer Controller must be configured to synchronize internal information system clocks using redundant authoritative time sources.'
  desc  "
    In NSX-ALB Clustered environment, the loss of connectivity to a particular authoritative time source will result in the loss of time synchronization (free-run mode) and increasingly inaccurate time stamps on audit events and other functions.

    Multiple time sources provide redundancy by including a secondary source. Time synchronization is usually a hierarchy; clients synchronize time to a local source while that source synchronizes its time to a more accurate source. The network device must utilize an authoritative time server and/or be configured to use redundant authoritative time sources. This requirement is related to the comparison done in CCI-001891.

    DoD-approved solutions consist of a combination of a primary and secondary time source using a combination or multiple instances of the following: a time server designated for the appropriate DoD network (NIPRNet/SIPRNet); United States Naval Observatory (USNO) time servers; and/or the Global Positioning System (GPS). The secondary time source must be located in a different geographic region than the primary time source.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the configured NTP servers are authoritative time sources.

    From the NSX ALB Controller web interface go to Administration >> System Settings >> DNS/NTP.

    If two or more authoritative time sources are not configured, this is a finding.

    If nonauthoritative time sources are configured, this is a finding.
  "
  desc 'fix', "
    From the NSX ALB Controller web interface go to Administration >> System Settings.

    Click the edit icon next to \"System Settings\".

    Under DNS/NTP, add or update the NTP Servers with authoritative sources for the environment and click Save.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000373-NDM-000298'
  tag gid: 'V-NALB-CO-000067'
  tag rid: 'SV-NALB-CO-000067'
  tag stig_id: 'NALB-CO-000067'
  tag cci: ['CCI-001893']
  tag nist: ['AU-8 (2)']

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
    describe 'Number of NTP servers' do
      subject { resultsjson['ntp_configuration']['ntp_servers'].size }
      it { should cmp >= 2 }
    end
    unless resultsjson['ntp_configuration']['ntp_servers'].empty?
      resultsjson['ntp_configuration']['ntp_servers'].each do |ntpserver|
        describe ntpserver do
          its(['server', 'addr']) { should be_in "#{input('allowed_ntp_servers')}" }
        end
      end
    end
  end
end
