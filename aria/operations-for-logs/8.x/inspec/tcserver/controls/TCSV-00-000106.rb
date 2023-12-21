control 'TCSV-00-000106' do
  title ' tc Server must set sslEnabledProtocols to an approved Transport Layer Security (TLS) version.'
  desc  "
    Transport Layer Security (TLS) is a required transmission protocol for a web server hosting controlled information. The use of TLS provides confidentiality of data in transit between the web server and client. FIPS 140-2 approved TLS versions must be enabled and non-FIPS-approved SSL versions must be disabled.

    NIST SP 800-52 defines the approved TLS versions for government applications.

    tc Server connections are managed by the Connector object class. The Connector object can be configured to use a range of transport encryption methods. Many older transport encryption methods have been proven to be weak. tc Server should be configured to use the sslEnabledProtocols correctly to ensure that older, less secure forms of transport security are not used.
  "
  desc  'rationale', ''
  desc  'check', "
    Navigate to and open $CATALINA_BASE/conf/server.xml.

    Navigate to each of the <Connector><SSLHostConfig> nodes.

    If the value of \"protocols\" is not set to one of \"TLSv1.2\", \"TLSv1.3\", \"TLSv1.2,TLSv1.3\", or is missing, this is a finding.

    EXAMPLE:
        <Connector port=\"443\"
                   ...
                    SSLEnabled=\"true\" sslProtocol=\"TLS\" sslEnabledProtocols=\"TLSv1.2\"
                   ...
        />
  "
  desc 'fix', "
    Navigate to and open $CATALINA_HOME/server.xml.

    Navigate to each of the <Connector> nodes configured to listen on a secure port.

    Configure each node with the setting 'sslEnabledProtocols=\"TLSv1.2\"'.

    EXAMPLE:
        <Connector port=\"443\"
                   ...
                    SSLEnabled=\"true\" sslProtocol=\"TLS\" sslEnabledProtocols=\"TLSv1.2\"
                   ...
        />

    Restart the service:
    # systemctl restart loginsight.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000439-AS-000155'
  tag satisfies: %w(SRG-APP-000440-AS-000167 SRG-APP-000442-AS-000259)
  tag gid: 'V-TCSV-00-000106'
  tag rid: 'SV-TCSV-00-000106'
  tag stig_id: 'TCSV-00-000106'
  tag cci: %w(CCI-002418 CCI-002421 CCI-002422)
  tag nist: ['SC-8', 'SC-8 (1)', 'SC-8 (2)']

  # Open server.xml file
  xmlconf = xml("#{input('catalinaBase')}/conf/server.xml")

  # loop through given list of allowed secure ports
  input('securePorts').each do |sp|
    # Get a count of connectors bound to that port
    conn = xmlconf["//*/Connector[@port='#{sp}']"].count
    if conn > 0
      # If connectors found, check the sslEnabledProtocols setting
      describe "Checking sslEnabledProtocols on connectors using secure port #{sp}" do
        subject { xmlconf["//Connector[@port='#{sp}']/@sslEnabledProtocols"] }
        it { should cmp ['TLSv1.2'] }
      end
    else
      describe "Checking for connectors bound to secure port #{sp}" do
        skip "No connectors bound to secure port #{sp}"
      end
    end
  end
end
