control 'UAGA-8X-000018' do
  title 'The UAG must be configured to comply with the required TLS settings in NIST SP 800-52.'
  desc  "
    Preventing the disclosure of transmitted information requires that the UAG take measures to employ strong cryptographic mechanisms to protect information during transmission. This is typically achieved through the use of Transport Layer Security (TLS).

    TLS must be enabled and non-FIPS-approved SSL versions must be disabled. NIST SP 800-52 specifies the preferred configurations for Government systems.

    According to NIST and as of publication, TLS 1.1 must not be used and TLS 1.2 must be configured.

    Note: Mandating TLS 1.2 may affect certain client types. Test and implement carefully.
  "
  desc  'rationale', ''
  desc  'check', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to Advanced Settings >> System Configuration.

    Verify the \"Enable TLS 1.0\" option is toggled to \"NO\".

    Verify the \"Enable TLS 1.1\" option is toggled to \"NO\".

    Verify the \"Enable TLS 1.2\" option is toggled \"YES\".

    If the setting for \"Enable TLS 1.0\" or \"Enable TLS 1.1\" is configured to \"YES\", or \"Enable TLS 1.2\" is configured to \"NO\", this is a finding.
  "
  desc 'fix', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to Advanced Settings >> System Configuration.

    Ensure the \"Enable TLS 1.0\" option is toggled to \"NO\".

    Ensure the \"Enable TLS 1.1\" option is toggled to \"NO\".

    Ensure the \"Enable TLS 1.2\" option is toggled \"YES\".

    Click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000062-ALG-000150'
  tag satisfies: ['SRG-NET-000147-ALG-000095', 'SRG-NET-000400-ALG-000097']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'UAGA-8X-000018'
  tag cci: ['CCI-000068', 'CCI-000197', 'CCI-001942']
  tag nist: ['AC-17 (2)', 'IA-2 (9)', 'IA-5 (1) (c)']

  result = uaghelper.runrestcommand('rest/v1/config/settings')

  describe result do
    its('status') { should cmp 200 }
  end

  # In current UAG version if FIPS is enabled, only TLSv1.2 is a valid option
  unless result.status != 200
    jsoncontent = json(content: result.body)
    describe jsoncontent do
      its(['systemSettings', 'tls10Enabled']) { should cmp false }
      its(['systemSettings', 'tls11Enabled']) { should cmp false }
      its(['systemSettings', 'tls12Enabled']) { should cmp true }
      its(['systemSettings', 'tls13Enabled']) { should cmp false }
    end
  end
end
