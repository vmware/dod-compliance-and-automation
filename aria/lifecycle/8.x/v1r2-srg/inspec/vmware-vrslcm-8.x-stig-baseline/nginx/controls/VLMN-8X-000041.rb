control 'VLMN-8X-000041' do
  title 'The VMware Aria Suite Lifecycle web service must use FIPS 140-2 validated cryptographic modules.'
  desc  "
    Encryption is only as good as the encryption modules utilized.  Unapproved cryptographic module algorithms cannot be verified, and cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised due to weak algorithms.

    FIPS 140-2 is the current standard for validating cryptographic modules and NSA Type-X (where X=1, 2, 3, 4) products are NSA-certified, hardware-based encryption modules.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the service is built with an OpenSSL module that is FIPS-140-2 validated.

    View the complied configuration by running the following command:

    # nginx -V

    Example output:

    built with OpenSSL 1.0.2za-fips  24 Aug 2021

    If the output does not display an OpenSSL module that is FIPS 140-2 validated, this is a finding.
  "
  desc 'fix', 'NGINX does not support altering this configuration after installation and must be re-built with a valid OpenSSL module in order to be fixed.'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000179-WSR-000110'
  tag satisfies: ['SRG-APP-000179-WSR-000111', 'SRG-APP-000224-WSR-000135', 'SRG-APP-000224-WSR-000136', 'SRG-APP-000224-WSR-000137', 'SRG-APP-000224-WSR-000139', 'SRG-APP-000416-WSR-000118']
  tag gid: 'V-VLMN-8X-000041'
  tag rid: 'SV-VLMN-8X-000041'
  tag stig_id: 'VLMN-8X-000041'
  tag cci: ['CCI-000803', 'CCI-001188', 'CCI-002450']
  tag nist: ['IA-7', 'SC-13', 'SC-23 (3)']

  describe.one do
    describe command('nginx -V') do
      its('stderr') { should match(/OpenSSL.*fips/) }
    end
  end
end
