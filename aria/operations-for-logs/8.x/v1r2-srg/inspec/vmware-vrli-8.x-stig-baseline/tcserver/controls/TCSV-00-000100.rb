control 'TCSV-00-000100' do
  title 'tc Server must use NSA Suite A cryptography when encrypting data that must be compartmentalized.'
  desc  "
    Cryptography is only as strong as the encryption modules/algorithms employed to encrypt the data. Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data.

    NSA has developed Type 1 algorithms for protecting classified information. The Committee on National Security Systems (CNSS) National Information Assurance Glossary (CNSS Instruction No. 4009) defines Type 1 products as:

    \"Cryptographic equipment, assembly or component classified or certified by NSA for encrypting and decrypting classified and sensitive national security information when appropriately keyed. Developed using established NSA business processes and containing NSA-approved algorithms are used to protect systems requiring the most stringent protection mechanisms.\"

    NSA-approved cryptography is required to be used for classified information system processing.

    The application server must utilize NSA-approved encryption modules when protecting classified data. This means using AES and other approved encryption modules.
  "
  desc  'rationale', ''
  desc  'check', "
    If the system is not implemented to process compartmentalized information, this requirement is Not Applicable.

    Navigate to and open $CATALINA_BASE/conf/server.xml.

    Navigate to each of the <Connector><SSLHostConfig> nodes.

    If the value of \"ciphers\" does not match the list of NSA Suite A ciphers or is missing, this is a finding.

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

    Navigate to each of the <Connector><SSLHostConfig> nodes.

    Configure the \"ciphers\" attribute with NSA Suite A approved ciphers.

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
        </Connector>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000416-AS-000140'
  tag gid: 'V-TCSV-00-000100'
  tag rid: 'SV-TCSV-00-000100'
  tag stig_id: 'TCSV-00-000100'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13']

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
