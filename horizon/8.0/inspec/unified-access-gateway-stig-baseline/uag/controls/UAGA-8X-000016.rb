control 'UAGA-8X-000016' do
  title 'The UAG must use encryption services that implement NIST FIPS-approved cryptography to protect the confidentiality of remote access sessions.'
  desc  "
    Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.

    Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include broadband connections, wireless connections, and proxied remote encrypted traffic (e.g., TLS gateways, web content filters, and webmail proxies), for example.

    Encryption provides a means to secure the remote connection so as to prevent unauthorized access to the data traversing the remote access connection, thereby providing a degree of confidentiality. The encryption strength of the mechanism is selected based on the security categorization of the information.
  "
  desc  'rationale', ''
  desc  'check', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to Advanced Settings >> System Configuration >> TLS Server Cipher Suites.

    Verify the UAG has been configured to use a list of NIST FIPS-approved cryptography suites, for example:

    \"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\"

    If the TLS Server Cipher Suites setting is not configured to use a list of NIST FIPS-approved cryptography suites, this is a finding.
  "
  desc 'fix', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to Advanced Settings >> System Configuration >> TLS Server Cipher Suites.

    Enter a list of NIST FIPS-approved cryptography suites, for example:

    \"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\"

    Click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000062-ALG-000011'
  tag satisfies: ['SRG-NET-000062-ALG-000092', 'SRG-NET-000063-ALG-000012', 'SRG-NET-000230-ALG-000113', 'SRG-NET-000510-ALG-000025', 'SRG-NET-000510-ALG-000040', 'SRG-NET-000510-ALG-000111']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'UAGA-8X-000016'
  tag cci: ['CCI-000068', 'CCI-001184', 'CCI-001453', 'CCI-002450']
  tag nist: ['AC-17 (2)', 'SC-13', 'SC-23']

  result = uaghelper.runrestcommand('rest/v1/config/settings')

  describe result do
    its('status') { should cmp 200 }
  end

  unless result.status != 200
    jsoncontent = json(content: result.body)

    describe jsoncontent['systemSettings']['cipherSuites'] do
      it { should_not cmp nil }
    end

    allowed = input('allowedCiphers')
    ciphers = jsoncontent['systemSettings']['cipherSuites'].split(',')

    ciphers.each do |cipher|
      describe allowed do
        it { should include cipher }
      end
    end
  end
end
