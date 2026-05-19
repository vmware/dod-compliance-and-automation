control 'VCFA-9X-000363' do
  title 'VMware Cloud Foundation must be configured to forward VCF Operations logs to a central log server.'
  desc  "
    Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

    Offloading is a common process in information systems with limited audit storage capacity.
  "
  desc  'rationale', ''
  desc  'check', "
    From VCF Operations, go to Infrastructure Operations >> Configurations >> Log Collection.

    Expand the \"VCF Operations\" section. For each VCF Operations instance listed select it and click Edit from the menu on the left to view the current log collection configuration.

    If log collection is not enabled and all logs are not configured to be forwarded, this is a finding.
  "
  desc 'fix', "
    In VCF, log collection and analysis is provided by VCF Operations for Logs.

    From VCF Operations, go to Infrastructure Operations >> Configurations >> Log Collection.

    Expand the \"VCF Operations\" section. For each VCF Operations instance listed select it and click Edit from the menu on the left.

    In the \"Collect Logs directly in Logs Cluster\" dropdown select an appropriate \"VCF Operations for Logs Server VIP\".

    Under \"Output logs to external log server\" click \"Select All\".

    Select a syslog protocol and optionally activate SSL and click Save.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000358'
  tag gid: 'V-VCFA-9X-000363'
  tag rid: 'SV-VCFA-9X-000363'
  tag stig_id: 'VCFA-9X-000363'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']

  response = http("https://#{input('operations_apihostname')}/suite-api/api/logs/forwarding",
                  method: 'GET',
                  ssl_verify: false,
                  headers: { 'Content-Type' => 'application/json',
                             'Accept' => 'application/json',
                             'Authorization' => "OpsToken #{input('operations_apitoken')}" })

  describe response do
    its('status') { should cmp 200 }
  end

  unless response.status != 200
    enabled = json(content: response.body)['enabled']
    describe 'Log forwarding must be enabled' do
      subject { enabled }
      it { should eq true }
    end

    unless !enabled
      logparams = ['ANALYTICS', 'COLLECTOR', 'TOMCAT_WEBAPP', 'VPOSTGRES', 'WATCHDOG', 'OTHER', 'CALL_STACK',
                   'GEMFIRE', 'WEB', 'VIEW_BRIDGE', 'SUITEAPI', 'UPGRADE', 'ADMIN_UI', 'VCOPS_BRIDGE']

      logentities = json(content: response.body)['entities']

      logparams.each do |entity|
        describe "The #{entity} log must be configured for offloading" do
          subject { entity }
          it { should be_in logentities }
        end
      end
    end
  end
end
