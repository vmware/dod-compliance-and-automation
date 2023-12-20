control 'TCSV-00-000002' do
  title 'tc Server Secured connectors must be configured to use strong encryption ciphers.'
  desc  "
    The tc Server has several remote communications channels. Examples are user requests via http/https, communication to a backend database, or communication to authenticate users. The encryption used to communicate must match the data that is being retrieved or presented.

    The Tomcat <Connector> element controls the TLS protocol and the associated ciphers used. If a strong cipher is not selected, an attacker may be able to circumvent encryption protections that are configured for the connector. Strong ciphers must be employed when configuring a secured connector.

    The configuration attribute and its values depend on what HTTPS implementation is being utilized. It may be either a Java-based implementation (e.g., JSSE — with BIO and/or NIO connectors), or an OpenSSL-based implementation (with an APR connector).

    TLSv1.2 or TLSv1.3 ciphers are configured via the server.xml file on a per connector basis. For a list of approved ciphers, refer to NIST SP 800-52 section 3.3.1.1.
  "
  desc  'rationale', ''
  desc  'check', "
    For Connectors, at the command prompt, run the following command:

    # xmllint -xpath \"//Connector/\" $CATALINA_BASE/conf/server.xml.

    Examine each <Connector> element that is not a redirect to a secure port. Identify the ciphers that are configured on each connector and determine if any of the ciphers are not secure.

    If ciphers are not defined, or insecure ciphers are configured for use, this is a finding.

    EXAMPLE:
        <Connector port=\"8443\" protocol=\"org.apache.coyote.http11.Http11AprProtocol\"
                   maxThreads=\"150\" SSLEnabled=\"true\" scheme=\"https\" secure=\"true\" >
            <UpgradeProtocol className=\"org.apache.coyote.http2.Http2Protocol\" />
            <SSLHostConfig honorCipherOrder=\"true\" disableCompression=\"true\" protocols=\"TLSv1.2,TLSv1.3\"
               ciphers=\"
                  TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                  TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                  TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
               \" >
                <Certificate certificateKeyFile=\"conf/certs/server-rsa.key\"
                             certificateFile=\"conf/certs/server-rsa.crt\"
                             type=\"RSA\" />
            </SSLHostConfig>
        </Connector>
  "
  desc 'fix', "
    Navigate to and open $CATALINA_HOME/server.xml.

    Navigate to each of the <Connector> nodes that is not a redirect to a secure port.

    Configure each <SSLHostConfig> node with the setting 'protocols=\"TLSv1.2\"'.

    EXAMPLE:
        <Connector port=\"8443\" protocol=\"org.apache.coyote.http11.Http11AprProtocol\"
                   maxThreads=\"150\" SSLEnabled=\"true\" scheme=\"https\" secure=\"true\" >
            <UpgradeProtocol className=\"org.apache.coyote.http2.Http2Protocol\" />
            <SSLHostConfig honorCipherOrder=\"true\" disableCompression=\"true\" protocols=\"TLSv1.2\"
               ciphers=\"
                  TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                  TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                  TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
               \" >
                <Certificate certificateKeyFile=\"conf/certs/server-rsa.key\"
                             certificateFile=\"conf/certs/server-rsa.crt\"
                             type=\"RSA\" />
            </SSLHostConfig>
        </Connector>\t

    Restart the service:
    # systemctl restart loginsight.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000014-AS-000009'
  tag satisfies: ['SRG-APP-000015-AS-000010']
  tag gid: 'V-TCSV-00-000002'
  tag rid: 'SV-TCSV-00-000002'
  tag stig_id: 'TCSV-00-000002'
  tag cci: %w(CCI-000068 CCI-001453)
  tag nist: ['AC-17 (2)']

  # Open server.xml file
  xmlconf = xml("#{input('catalinaBase')}/conf/server.xml")

  # loop through given list of allowed secure ports
  input('securePorts').each do |sp|
    # Get a count of connectors bound to that port
    conn = xmlconf["//*/Connector[@port='#{sp}']"].count
    if conn > 0
      # If connectors found, check the ciphers setting
      lst = xmlconf["//Connector[@port='#{sp}']/@ciphers"].join(' ').gsub("\r", '').gsub("\n", '').gsub('"', '').gsub(' ', '').split(',')
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
