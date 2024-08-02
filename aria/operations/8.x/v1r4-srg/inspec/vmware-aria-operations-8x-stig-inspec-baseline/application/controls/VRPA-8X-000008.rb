control 'VRPA-8X-000008' do
  title 'VMware Aria Operations must use DoD- or CNSS-approved PKI Class 3 or Class 4 certificates.'
  desc  'Class 3 PKI certificates are used for servers and software signing rather than for identifying individuals. Class 4 certificates are used for business-to-business transactions. Utilizing unapproved certificates not issued or approved by DoD or CNS creates an integrity risk. The application server must utilize approved DoD or CNS Class 3 or Class 4 certificates for software signing and business-to-business transactions.'
  desc  'rationale', ''
  desc  'check', "
    Login to the vRealize Operations Manager admin portal (/admin/) as an administrator.

    In the upper right corner, click the certificate icon.

    If the \"Certificate Information\" does not show a valid, DoD-issued certificate, this is a finding.
  "
  desc 'fix', "
    Obtain a web server certificate from the proper DoD authority.

    Prepare the certificate, private key, intermediate(s) and root as one continuous concatenated PEM file as shown below:

    -----BEGIN CERTIFICATE-----
    (Your Primary SSL certificate: your_domain_name.crt)
    -----END CERTIFICATE-----
    -----BEGIN RSA PRIVATE KEY-----
    (Your Private Key: your_domain_name.key)
    -----END RSA PRIVATE KEY-----
    -----BEGIN CERTIFICATE-----
    (Your Intermediate certificate: DoD CA 34.crt)
    -----END CERTIFICATE-----
    -----BEGIN CERTIFICATE-----
    (Your Root certificate: DoD Root CA 2.crt)
    -----END CERTIFICATE-----

    Login to the vRealize Operations Manager admin portal (/admin/) as an administrator.

    In the upper right corner, click the certificate icon.

    Click the \"Install new certificate\" button\".

    Click \"Browse...\" and select your PEM file from above.

    Validate that the certificate information is correct and click \"Install\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000514-AS-000137'
  tag satisfies: ['SRG-APP-000427-AS-000264']
  tag gid: 'V-VRPA-8X-000008'
  tag rid: 'SV-VRPA-8X-000008'
  tag stig_id: 'VRPA-8X-000008'
  tag cci: ['CCI-002450', 'CCI-002470']
  tag nist: ['SC-13 b', 'SC-23 (5)']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
