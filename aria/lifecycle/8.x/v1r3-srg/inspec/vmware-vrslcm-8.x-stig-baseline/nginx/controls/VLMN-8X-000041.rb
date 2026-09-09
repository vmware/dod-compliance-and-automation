control 'VLMN-8X-000041' do
  title 'The VMware Aria Suite Lifecycle web service must use FIPS 140-2 validated cryptographic modules.'
  desc  "
    Encryption is only as good as the encryption modules utilized.  Unapproved cryptographic module algorithms cannot be verified, and cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised due to weak algorithms.

    FIPS 140-2 is the current standard for validating cryptographic modules and NSA Type-X (where X=1, 2, 3, 4) products are NSA-certified, hardware-based encryption modules.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the service is built with an OpenSSL module that is FIPS-140-2 validated.

    View the compiled configuration by running the following command:

    # nginx -V

    Example output (OpenSSL 1.x):

    built with OpenSSL 1.0.2za-fips  24 Aug 2021

    Example output (OpenSSL 3.x):

    built with OpenSSL 3.0.16 11 Feb 2025

    For OpenSSL 1.x, if the version string does not include the \"-fips\" suffix, this is a finding.

    For OpenSSL 3.x, FIPS is a loadable provider and will not appear in the nginx -V output. Verify the FIPS provider is active by running:

    # openssl list -providers

    If the output does not include a \"fips\" provider entry, also verify the kernel FIPS mode is enabled by running:

    # sudo sysctl -a | grep fips

    Expected output:

    crypto.fips_enabled = 1

    If neither the \"fips\" provider entry nor crypto.fips_enabled = 1 is present, this is a finding.
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

  nginx_v_stderr = command('nginx -V').stderr
  openssl_major = nginx_v_stderr.match(/OpenSSL\s+(\d+)\.\d+/)&.captures&.first.to_i

  if openssl_major >= 3
    # OpenSSL 3.x: FIPS is a loadable provider, not embedded in the version string.
    # Pass if either the OpenSSL FIPS provider is active OR the kernel has FIPS mode enabled.
    describe.one do
      describe command('openssl list -providers') do
        its('stdout') { should match(/fips/i) }
      end
      describe command('sudo sysctl -a 2>/dev/null | grep fips') do
        its('stdout') { should match(/crypto\.fips_enabled\s*=\s*1/) }
      end
    end
  else
    # OpenSSL 1.x: FIPS suffix is compiled into the version string (e.g. 1.0.2za-fips).
    describe command('nginx -V') do
      its('stderr') { should match(/OpenSSL\s+\S*fips/i) }
    end
  end
end
