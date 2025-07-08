control 'NALB-SE-000018' do
  title 'The NSX Advanced Load Balancer must use secure versions of TLS.'
  desc  "
    SP 800-52 provides guidance on using the most secure version and configuration of the TLS/SSL protocol. Using older unauthorized versions or incorrectly configuring protocol negotiation makes the gateway vulnerable to known and unknown attacks which exploit vulnerabilities in this protocol.

    This requirement applies to TLS gateways (also known as SSL gateways) and is not applicable to VPN devices. Application protocols such as HTTPS and DNSSEC use TLS as the underlying security protocol thus are in scope for this requirement. NIS SP 800-52r2 provides guidance.

    SP 800-52r2 sets TLS version 1.2 as a minimum version.
  "
  desc  'rationale', ''
  desc  'check', "
    Review virtual services that have SSL profiles applied to determine what TLS versions are enforced.

    From the NSX ALB Controller web interface go to Applications >> Virtual Services.

    For each virtual service, select edit on the \"Virtual Service\" to view the configuration.

    Under \"SSL Settings\" click Edit on the SSL Profile and review the \"Accepted Versions\" field.

    If anything other than TLS 1.2 or 1.3 is enabled, this is a finding.

    If a virtual service does NOT have SSL enabled, this is Not Applicable.
  "
  desc 'fix', "
    To update a virtual service SSL Profile, do the following:

    From the NSX ALB Controller web interface go to Applications >> Virtual Services.

    Select edit on the target \"Virtual Service\".

    Under \"SSL Profile\" either select a profile with only the required protocols enabled, update the existing profile, or create a new profile then click Save.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-NET-000062-ALG-000150'
  tag satisfies: ['SRG-NET-000230-ALG-000113']
  tag gid: 'V-NALB-SE-000018'
  tag rid: 'SV-NALB-SE-000018'
  tag stig_id: 'NALB-SE-000018'
  tag cci: ['CCI-000068', 'CCI-001184']
  tag nist: ['AC-17 (2)', 'SC-23']

  virtualservices = http("https://#{input('avicontroller')}/api/virtualservice",
                      method: 'GET',
                      headers: {
                        'Accept-Encoding' => 'application/json',
                        'X-Avi-Version' => "#{input('aviversion')}",
                        'Cookie' => "sessionid=#{input('sessionCookieId')}",
                      },
                      ssl_verify: false)

  describe virtualservices do
    its('status') { should cmp 200 }
  end

  unless virtualservices.status != 200
    vsjson = JSON.parse(virtualservices.body)
    if vsjson['results'] == []
      impact 0.0
      describe 'No Virtual Services found!' do
        skip 'No Virtual Services found!...skipping.'
      end
    else
      # To keep track of # of virtual servers with ssl enabled
      sslcount = 0
      vsjson['results'].each do |vs|
        next unless vs.key?('ssl_profile_ref')
        # Find ssl profile reference to check TLS versions
        ssl_profile_ref = vs['ssl_profile_ref']
        vsname = vs['name']
        ssl_profile_response = http(ssl_profile_ref,
                                method: 'GET',
                                headers: {
                                  'Accept-Encoding' => 'application/json',
                                  'X-Avi-Version' => "#{input('aviversion')}",
                                  'Cookie' => "sessionid=#{input('sessionCookieId')}",
                                },
                                ssl_verify: false)

        describe ssl_profile_response do
          its('status') { should cmp 200 }
        end

        unless ssl_profile_response.status != 200
          ssl_profile_json = json(content: ssl_profile_response.body)
          ssl_profile_json['accepted_versions'].each do |ssl_version|
            describe "Virtual Server: #{vsname} with configured SSL/TLS version #{ssl_version['type']}" do
              subject { ssl_version['type'] }
              it { should be_in ['SSL_VERSION_TLS1_2', 'SSL_VERSION_TLS1_3'] }
            end
          end
        end
        # Increment # of ssl enabled virtual servers
        sslcount += 1
      end
      unless sslcount != 0
        impact 0.0
        describe 'No virtual services found with SSL/TLS services enabled.' do
          skip 'No virtual services found with SSL/TLS services enabled.'
        end
      end
    end
  end
end
