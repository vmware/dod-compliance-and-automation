control 'NALB-SE-000047' do
  title 'The NSX Advanced Load Balancer must terminate all network connections associated with a communications session at the end of the session or after 10 minutes of inactivity.'
  desc  "
    Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element.

    Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, and de-allocating networking assignments at the application level if multiple application sessions are using a single operating system level network connection.

    ALGs may provide session control functionality as part of content filtering, load balancing, or proxy services.
  "
  desc  'rationale', ''
  desc  'check', "
    Review the NSX ALB Virtual Service TCP Proxy \"Idle Duration\" setting.

    From the NSX ALB Controller web interface go to Applications >> Virtual Services.

    For each virtual service, select Edit on the \"Virtual Service\" to view the configuration.

    For each profile listed in the TCP/UDP profile dropdown, click Edit to view the profile details.

    If the configured TCP/UDP profile is not of type \"TCP Proxy\", this is not applicable.

    If \"TCP Proxy\" is configured to \"Auto Learn\", this is not a finding.

    If \"TCP Proxy\" is set to Custom, and \"Idle Duration\" is set to a value greater than 600, or is set to zero, this is a finding.
  "
  desc 'fix', "
    Configure the NSX ALB Virtual Service TCP Proxy \"Idle Duration\" setting.

    From the NSX ALB Controller web interface go to Applications >> Virtual Services.

    For each virtual service, select Edit on the \"Virtual Service\" to update the configuration.

    Under Settings >> Profiles >> TCP/UDP Profile >> Create or Edit an appropriate TCP/UDP Profile.

    Under TCP Proxy, choose Custom.

    Ensure the idle duration is set to a value less than or equal to 600, and not zero.

    Click \"Save\", then \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000213-ALG-000107'
  tag gid: 'V-NALB-SE-000047'
  tag rid: 'SV-NALB-SE-000047'
  tag stig_id: 'NALB-SE-000047'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']

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
      vsjson['results'].each do |vs|
        # Get the TCP Network profile for this virtual server
        network_profile_ref = vs['network_profile_ref']
        vsname = vs['name']
        network_profile_response = http(network_profile_ref,
                                    method: 'GET',
                                    headers: {
                                      'Accept-Encoding' => 'application/json',
                                      'X-Avi-Version' => "#{input('aviversion')}",
                                      'Cookie' => "sessionid=#{input('sessionCookieId')}",
                                    },
                                    ssl_verify: false)

        describe network_profile_response do
          its('status') { should cmp 200 }
        end

        next unless network_profile_response.status != 200
        network_profile_json = json(content: network_profile_response.body)
        next unless network_profile_json['profile']['type'] == 'PROTOCOL_TYPE_TCP_PROXY'
        npname = network_profile_json['name']
        describe.one do
          describe "Virtual Service: #{vsname} with configured TCP/UCP Profile: #{npname}" do
            subject { network_profile_json['profile']['tcp_proxy_profile']['automatic'] }
            it { should cmp true }
          end
          describe "Virtual Service: #{vsname} with configured TCP/UCP Profile: #{npname}" do
            subject { network_profile_json['profile']['tcp_proxy_profile']['idle_connection_timeout'] }
            it { should cmp <= 600 }
            it { should cmp > 0 }
          end
        end
      end
    end
  end
end
