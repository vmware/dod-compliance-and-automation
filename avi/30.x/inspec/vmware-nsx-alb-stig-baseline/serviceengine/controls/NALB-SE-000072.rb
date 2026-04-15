control 'NALB-SE-000072' do
  title 'The NSX Advanced Load Balancer must enable WAF policy signatures to detect and prevent code injection attacks.'
  desc  "
    Data mining is the analysis of large quantities of data to discover patterns and is used in intelligence gathering. Failure to prevent attacks launched against organizational information from unauthorized data mining may result in the compromise of information.

    Injection attacks allow an attacker to inject code into a program or query or inject malware onto a computer to execute remote commands that can read or modify a database, or change data on a website. Web applications frequently access databases to store, retrieve, and update information. An attacker can construct inputs that the database will execute. This is most commonly referred to as a code injection attack. This type of attack includes XPath and LDAP injections.

    These attacks also include buffer overrun, XML, JavaScript, and HTML injections.

    Compliance requires the ALG to have the capability to prevent code injections. Examples include a Web Application Firewalls (WAFs) or database application gateways.
  "
  desc  'rationale', ''
  desc  'check', "
    Review the NSX ALB Virtual Services to verify WAF CRS groups are enabled.

    From the NSX ALB Controller web interface go to Applications >> Virtual Services.

    For each virtual service, select edit on the \"Virtual Service\" to view the configuration.

    Select edit on the \"WAF Policy\" and under \"Signatures\" review the CRS groups.

    If the \"WAF Policy\" assigned does not have the \"CRS_920_Protocol_Validation\", \"CRS_931_Application_Attack_RFI\", \"CRS_932_Application_Attack_RCE\", and \"CRS_942_Application_Attack_SQLi\" CRS groups enabled, this is a finding.

    If the virtual service is not configured with an application profile of type \"HTTP\", this is not a finding.
  "
  desc 'fix', "
    To apply a \"WAF Policy\" to a virtual service, do the following:

    From the NSX ALB Controller web interface go to Applications >> Virtual Services.

    Select edit on the target \"Virtual Service\".

    Go to Settings >> Profiles >> WAF Policy >> Select or Create an appropriate WAF Policy with the following CRS groups enabled at a minimum:

    CRS_920_Protocol_Validation
    CRS_931_Application_Attack_RFI
    CRS_932_Application_Attack_RCE
    CRS_942_Application_Attack_SQLi

    Click Save to apply the configuration.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000318-ALG-000014'
  tag satisfies: ['SRG-NET-000318-ALG-000152', 'SRG-NET-000319-ALG-000015', 'SRG-NET-000319-ALG-000020', 'SRG-NET-000380-ALG-000128', 'SRG-NET-000401-ALG-000127', 'SRG-NET-000512-ALG-000066']
  tag gid: 'V-NALB-SE-000072'
  tag rid: 'SV-NALB-SE-000072'
  tag stig_id: 'NALB-SE-000072'
  tag cci: ['CCI-000366', 'CCI-001310', 'CCI-002346', 'CCI-002347', 'CCI-002754']
  tag nist: ['AC-23', 'CM-6 b', 'SI-10', 'SI-10 (3)']

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
      # To count if we do not find an eligible vs to inspect
      httpcount = 0
      vsjson['results'].each do |vs|
        # Determine if virtual server application profile is of type HTTP. WAF only applies to HTTP profiles.
        app_profile_ref = vs['application_profile_ref']

        app_profile_response = http(app_profile_ref,
                                      method: 'GET',
                                      headers: {
                                        'Accept-Encoding' => 'application/json',
                                        'X-Avi-Version' => "#{input('aviversion')}",
                                        'Cookie' => "sessionid=#{input('sessionCookieId')}",
                                      },
                                      ssl_verify: false)

        describe app_profile_response do
          its('status') { should cmp 200 }
        end

        next unless app_profile_response.status == 200
        app_profile_json = json(content: app_profile_response.body)

        # Skip virtual server if it does not have an http profile
        next unless app_profile_json['type'] == 'APPLICATION_PROFILE_TYPE_HTTP'
        # Increment # of elible certs found
        httpcount += 1
        # Find waf profile reference to check
        waf_policy_ref = vs['waf_policy_ref']
        vsname = vs['name']
        if waf_policy_ref.nil?
          describe "WAF policy on virtual service: #{vs['name']}" do
            subject { waf_policy_ref }
            it { should_not be_nil }
          end
        else
          waf_policy_response = http(waf_policy_ref,
                                  method: 'GET',
                                  headers: {
                                    'Accept-Encoding' => 'application/json',
                                    'X-Avi-Version' => "#{input('aviversion')}",
                                    'Cookie' => "sessionid=#{input('sessionCookieId')}",
                                  },
                                  ssl_verify: false)

          describe waf_policy_response do
            its('status') { should cmp 200 }
          end

          unless waf_policy_response.status != 200
            waf_policy_json = json(content: waf_policy_response.body)
            waf_crs_ref = waf_policy_json['waf_crs_ref']
            waf_crs_response = http(waf_crs_ref,
                                    method: 'GET',
                                    headers: {
                                      'Accept-Encoding' => 'application/json',
                                      'X-Avi-Version' => "#{input('aviversion')}",
                                      'Cookie' => "sessionid=#{input('sessionCookieId')}",
                                    },
                                    ssl_verify: false)

            describe waf_crs_response do
              its('status') { should cmp 200 }
            end

            unless waf_crs_response.status != 200
              waf_crs_json = json(content: waf_crs_response.body)
              waf_crs_json['groups'].each do |group|
                # Process only the groups we are interested in
                next unless ['CRS_920_Protocol_Validation', 'CRS_931_Application_Attack_RFI', 'CRS_932_Application_Attack_RCE', 'CRS_942_Application_Attack_SQLi'].include?(group['name'])
                describe "Virtual Server: #{vsname} with configured WAF policy: #{waf_policy_json['name']} and CRS Group: #{group['name']}" do
                  subject { group['enable'] }
                  it { should cmp true }
                end
              end
            end
          end
        end
      end
      unless httpcount != 0
        impact 0.0
        describe 'No virtual servers found with HTTP application profiles so this is not applicable.' do
          skip 'No virtual servers found with HTTP application profiles so this is not applicable.'
        end
      end
    end
  end
end
