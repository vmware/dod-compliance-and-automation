control 'WOAT-3X-000005' do
  title 'Workspace ONE Access must be configured with FIPS 140-2 compliant ciphers for HTTPS connections.'
  desc  "
    Encryption of data-in-flight is an essential element of protecting information confidentiality.  If a web server uses weak or outdated encryption algorithms, then the server's communications can potentially be compromised.

    The US Federal Information Processing Standards (FIPS) publication 140-2, Security Requirements for Cryptographic Modules (FIPS 140-2) identifies eleven areas for a cryptographic module used inside a security system that protects information.  FIPS 140-2 approved ciphers provide the maximum level of encryption possible for a private web server.

    Configuration of ciphers used by TC Server are set in the catalina.properties file.  Only those ciphers specified in the configuration file, and which are available in the installed OpenSSL library, will be used by TC Server while encrypting data for transmission.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # grep \"nio-ssl.cipher.list\" /opt/vmware/horizon/workspace/conf/catalina.properties

    Expected result:

    nio-ssl.cipher.list=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /opt/vmware/horizon/workspace/conf/catalina.properties

    Navigate to the nio-ssl.cipher.list node and configure it as follows:

    nio-ssl.cipher.list=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000014-WSR-000006'
  tag satisfies: ['SRG-APP-000416-WSR-000118', 'SRG-APP-000439-WSR-000151']
  tag gid: 'V-WOAT-3X-000005'
  tag rid: 'SV-WOAT-3X-000005'
  tag stig_id: 'WOAT-3X-000005'
  tag cci: ['CCI-000068', 'CCI-002418', 'CCI-002450']
  tag nist: ['AC-17 (2)', 'SC-13', 'SC-8']

  describe parse_config_file("#{input('catalinaPropertiesPath')}").params['nio-ssl.cipher.list'] do
    it { should cmp "#{input('sslCipherList')}" }
  end
end
