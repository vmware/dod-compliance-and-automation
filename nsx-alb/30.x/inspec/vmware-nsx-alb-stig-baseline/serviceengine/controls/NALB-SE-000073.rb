control 'NALB-SE-000073' do
  title 'The NSX Advanced Load Balancer must enable a WAF policy in enforcement mode on virtual services to prevent attacks.'
  desc  "
    Data mining is the analysis of large quantities of data to discover patterns and is used in intelligence gathering. Failure to prevent attacks launched against organizational information from unauthorized data mining may result in the compromise of information.

    Injection attacks allow an attacker to inject code into a program or query or inject malware onto a computer to execute remote commands that can read or modify a database, or change data on a website. These attacks include buffer overrun, XML, JavaScript, and HTML injections.

    Compliance requires the ALG to have the capability to prevent code injections. Examples include a Web Application Firewalls (WAFs) or database application gateways.
  "
  desc  'rationale', ''
  desc  'check', "
    Review the NSX ALB Virtual Services to verify if a WAF policy is enabled.

    From the NSX ALB Controller web interface go to Applications >> Virtual Services.

    For each virtual service, select edit on the \"Virtual Service\" to view the configuration.

    Select edit on the \"WAF Policy\" to view the configuration.

    If the \"WAF Policy\" assigned is not in enforcement mode, this is a finding.

    If the virtual service is not configured with an application profile of type \"HTTP\", this is not a finding.
  "
  desc 'fix', "
    To apply a \"WAF Policy\" to a virtual service, do the following:

    From the NSX ALB Controller web interface go to Applications >> Virtual Services.

    Select edit on the target \"Virtual Service\".

    Go to Settings >> Profiles >> WAF Policy >> Select or Create an appropriate WAF Policy with enforcement mode enabled and then click Save.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000318-ALG-000151'
  tag satisfies: ['SRG-NET-000019-ALG-000018']
  tag gid: 'V-NALB-SE-000073'
  tag rid: 'SV-NALB-SE-000073'
  tag stig_id: 'NALB-SE-000073'
  tag cci: ['CCI-001414', 'CCI-002346']
  tag nist: ['AC-23', 'AC-4']

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
            describe "Virtual Server: #{vsname} with configured WAF policy: #{waf_policy_json['name']}" do
              subject { waf_policy_json['mode'] }
              it { should cmp 'WAF_MODE_ENFORCEMENT' }
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
