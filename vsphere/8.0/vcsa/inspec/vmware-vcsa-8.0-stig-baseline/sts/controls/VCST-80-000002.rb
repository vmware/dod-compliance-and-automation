control 'VCST-80-000002' do
  title 'The vCenter STS service must be configured to use strong encryption ciphers.'
  desc  "
    Tomcat has several remote communications channels. Examples are user requests via http/https, communication to a backend database, or communication to authenticate users. The encryption used to communicate must match the data that is being retrieved or presented.

    The Tomcat <Connector> element controls the TLS protocol and the associated ciphers used. If a strong cipher is not selected, an attacker may be able to circumvent encryption protections that are configured for the connector. Strong ciphers must be employed when configuring a secured connector.

    TLSv1.2 or TLSv1.3 ciphers are configured via the server.xml file on a per connector basis. For a list of approved ciphers, refer to NIST SP 800-52 section 3.3.1.1.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # xmllint --xpath '/Server/Service/Connector/SSLHostConfig/@ciphers' /usr/lib/vmware-sso/vmware-sts/conf/server.xml

    Expected result:

    ciphers=\"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256\"

    If each result returned does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-sso/vmware-sts/conf/server.xml

    For each connector with \"SSLEnabled\" set to true, configure the ciphers attribute under the \"SSLHostConfig\" as follows:

    ciphers=\"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256\"

    Restart the service with the following command:

    # vmon-cli --restart sts
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000014-AS-000009'
  tag satisfies: ['SRG-APP-000015-AS-000010']
  tag gid: 'V-VCST-80-000002'
  tag rid: 'SV-VCST-80-000002'
  tag stig_id: 'VCST-80-000002'
  tag cci: ['CCI-000068', 'CCI-001453']
  tag nist: ['AC-17 (2)']

  # Open server.xml file
  xmlconf = xml(input('serverXmlPath'))

  # loop through given list of allowed secure ports
  input('securePorts').each do |sp|
    # Get a count of connectors bound to that port
    conn = xmlconf["//*/Connector[@port='#{sp}']"].count
    if conn > 0
      # If connectors found, check the ciphers setting
      lst = xmlconf["//Connector[@port='#{sp}']/SSLHostConfig/@ciphers"].join(' ').gsub("\r", '').gsub("\n", '').gsub('"', '').gsub(' ', '').split(',')
      lst.each do |cipher|
        describe cipher do
          it { should be_in input('allowedCiphers') }
        end
      end
    else
      describe "Checking for connectors bound to secure port #{sp}" do
        skip "No connectors bound to secure port #{sp}"
      end
    end
  end
end
