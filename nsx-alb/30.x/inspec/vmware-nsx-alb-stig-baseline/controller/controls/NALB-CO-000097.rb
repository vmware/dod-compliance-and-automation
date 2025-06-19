control 'NALB-CO-000097' do
  title 'The NSX Advanced Load Balancer Controller must disable insecure SSH ciphers.'
  desc  'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.'
  desc  'rationale', ''
  desc  'check', "
    Review the access settings to verify insecure SSH ciphers are disabled.

    From the NSX ALB Controller web interface go to Administration >> System Settings >> Access.

    If \"Allowed Ciphers\" is configured to \"aes128-ctr,aes256-ctr\" or a subset thereof, this is not a finding.

    If \"Allowed Ciphers\" contains any ciphers not in \"aes128-ctr,aes256-ctr\", this is a finding.
  "
  desc 'fix', "
    To configure the \"Allowed Ciphers\", do the following:

    From the NSX ALB Controller web interface go to Administration >> System Settings.

    Click the edit icon next to the \"System Settings\".

    Update the \"Allowed Ciphers\" field to \"aes128-ctr,aes256-ctr\" and click Save.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag gid: 'V-NALB-CO-000097'
  tag rid: 'SV-NALB-CO-000097'
  tag stig_id: 'NALB-CO-000097'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

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
    resultsjson['ssh_ciphers'].each do |cipher|
      describe "Configured SSH cipher: #{cipher}" do
        subject { cipher }
        it { should be_in ['aes128-ctr', 'aes256-ctr'] }
      end
    end
  end
end
