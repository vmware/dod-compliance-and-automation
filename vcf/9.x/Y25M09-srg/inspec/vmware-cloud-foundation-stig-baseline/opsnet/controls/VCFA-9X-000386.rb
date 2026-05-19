control 'VCFA-9X-000386' do
  title 'VMware Cloud Foundation Operations for Networks must be configured to forward logs to a central log server.'
  desc  "
    Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

    Offloading is a common process in information systems with limited audit storage capacity.
  "
  desc  'rationale', ''
  desc  'check', "
    If VCF Operations for Networks is not deployed, this is not applicable.

    From VCF Operations for Networks, go to Settings >> Logs >> Syslog Configuration.

    Review the syslog configuration.

    If the syslog is not enabled and all sources configured to forwarded to an authorized central log server, this is a finding.
  "
  desc 'fix', "
    From VCF Operations for Networks, go to Settings >> Logs >> Syslog Configuration.

    Click \"Add Server\" and configure one or more authorized central log servers.

    Click the radio button next to \"Enable Syslog\".

    For each source click the edit icon. Select a target syslog server and click \"Submit\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000358'
  tag gid: 'V-VCFA-9X-000386'
  tag rid: 'SV-VCFA-9X-000386'
  tag stig_id: 'VCFA-9X-000386'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']

  if input('opsnet_deployed')
    # Check to see if syslog is enabled
    response = http("https://#{input('opsnet_apihostname')}/api/ni/settings/syslog/status",
                    method: 'GET',
                    ssl_verify: false,
                    headers: { 'Content-Type' => 'application/json',
                               'Accept' => 'application/json',
                               'Authorization' => "NetworkInsight #{input('opsnet_apitoken')}" })

    describe response do
      its('status') { should cmp 200 }
    end

    unless response.status != 200
      responseval = json(content: response.body)
      syslogenabled = responseval['enabled']
      describe 'Enable Syslog' do
        subject { syslogenabled }
        it { should cmp true }
      end
      if syslogenabled
        # Check to see if configured servers are authorized
        response = http("https://#{input('opsnet_apihostname')}/api/ni/settings/syslog",
                        method: 'GET',
                        ssl_verify: false,
                        headers: { 'Content-Type' => 'application/json',
                                   'Accept' => 'application/json',
                                   'Authorization' => "NetworkInsight #{input('opsnet_apitoken')}" })

        describe response do
          its('status') { should cmp 200 }
        end

        unless response.status != 200
          responseval = json(content: response.body)
          if responseval['data'] == []
            describe 'Configured syslog servers' do
              subject { responseval['data'] }
              it { should_not cmp [] }
            end
          else
            responseval['data'].each do |syslogserver|
              describe "Configured syslog server: #{syslogserver['ip_or_fqdn']}" do
                subject { syslogserver['ip_or_fqdn'] }
                it { should be_in input('opsnet_syslogServers') }
              end
            end
          end
        end

        # Check to see if sources are mapped to an authorized server
        response = http("https://#{input('opsnet_apihostname')}/api/ni/settings/syslog/mapping",
                        method: 'GET',
                        ssl_verify: false,
                        headers: { 'Content-Type' => 'application/json',
                                   'Accept' => 'application/json',
                                   'Authorization' => "NetworkInsight #{input('opsnet_apitoken')}" })

        describe response do
          its('status') { should cmp 200 }
        end

        unless response.status != 200
          responseval = json(content: response.body)
          responseval['data'].each do |mapping|
            describe "Source: #{mapping['syslog_source']} with mapping: #{mapping['syslog_ip']}" do
              subject { mapping['syslog_ip'] }
              it { should be_in input('opsnet_syslogServers') }
            end
          end
        end
      end
    end
  else
    impact 0.0
    describe 'VCF Operations for Networks is not deployed in the target environment. This control is N/A.' do
      skip 'VCF Operations for Networks is not deployed in the target environment. This control is N/A.'
    end
  end
end
