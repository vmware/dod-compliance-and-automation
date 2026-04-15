control 'NALB-SE-000004' do
  title 'The NSX Advanced Load Balancer must immediately use updates made to WAF signatures.'
  desc  "
    Information flow policies regarding dynamic information flow control include, for example, allowing or disallowing information flows based on changes to the PPSM CAL, vulnerability assessments, or mission conditions. Changing conditions include changes in the threat environment and detection of potentially harmful or adverse events.

    Changes to the ALG must take effect when made by an authorized administrator and the new configuration is put in place or committed, including upon restart or the application or reboot of the system. With some devices, the changes take effect as the configuration is changed, while with others, the new configuration must be submitted to the device. In any case, the behavior of the ALG must immediately be affected to reflect the configuration change.
  "
  desc  'rationale', ''
  desc  'check', "
    Review the NSX ALB Virtual Services to verify WAF CRS group signature updates are enabled when updates are available.

    From the NSX ALB Controller web interface go to Applications >> Virtual Services.

    For each virtual service, select edit on the \"Virtual Service\" to view the configuration.

    Select edit on the \"WAF Policy\" and under \"Signatures\" review the CRS groups.

    If the \"WAF Policy\" assigned does not have \"Enable CRS auto-update\" enabled, this is a finding.

    If the virtual service is not configured with an application profile of type \"HTTP\", this is not a finding.
  "
  desc 'fix', "
    To apply a \"WAF Policy\" to a virtual service, do the following:

    From the NSX ALB Controller web interface go to Applications >> Virtual Services.

    Select edit on the target \"Virtual Service\".

    Go to Settings >> Profiles >> WAF Policy >> Select or Create an appropriate WAF Policy.

    Under Signatures >> CRS Groups enable \"Enable CRS auto-update\" and click Save to apply the configuration.

    Note: The Enable CRS auto-update option when selected keeps the CRS version used in this policy updated. If a newer CRS object is available on the Controller, the system initiates the CRS upgrade process for this WAF Policy. It will not update polices if the current CRS version is set as CRS-VERSION-NOT-APPLICABLE.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000019-ALG-000019'
  tag gid: 'V-NALB-SE-000004'
  tag rid: 'SV-NALB-SE-000004'
  tag stig_id: 'NALB-SE-000004'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']

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
            describe "Virtual Server: #{vsname} with configured WAF policy: #{waf_policy_json['name']} CRS auto update" do
              subject { waf_policy_json['auto_update_crs'] }
              it { should cmp true }
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
