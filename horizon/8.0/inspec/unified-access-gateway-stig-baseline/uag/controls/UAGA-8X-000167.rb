control 'UAGA-8X-000167' do
  title 'The UAG must be configured with a DoD-issued TLS certificate.'
  desc  "
    Machines on a DoD network must only accept PKI certificates obtained from a DoD-approved internal or external certificate authority (CA). If the CA used for verifying the certificate is not DoD-approved, trust of the CA will not be established.

    The UAG supports the replacement of the default, self-signed certificate with one issued by a DoD CA.
  "
  desc  'rationale', ''
  desc  'check', "
    From within the UAG administrative user interface, there is no way to view the uploaded certificate information. Therefore, two options exist for checking compliance.

    Option One - re-upload known DoD issued certificate:

    > Login to the UAG administrative interface as an administrator.

    > Select \"Configure Manually\".

    > Navigate to Advanced Settings >> TLS Server Certificate Settings.

    > Select the certificate type and network interfaces to apply the certificate to, then upload valid DoD issued certificate files into the required fields.

    > Click \"Save\".

    Option Two - verify the certificate through the browser:

    > Navigate to the UAG login page (user and/or admin page, depending on environment setup).

    > In the browser's URL address bar, find the certificate settings validating the site is secure, and select to \"View Certificate\" (each browser is different).

    > In the Certificate dialog, click the \"Details\" tab, then the \"Issuer\" field.

    > Validate the Issuer is on the DoD approved issuer list.

    If the UAG does not utilize certificates that have been issued by a DoD approved Certificate Authority (CA), this is a finding.
  "
  desc 'fix', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to Advanced Settings >> TLS Server Certificate Settings.

    Select the certificate type and network interfaces to apply the certificate to, then upload valid DoD issued certificate files into the required fields.

    Click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000512-ALG-000062'
  tag gid: 'V-UAGA-8X-000167'
  tag rid: 'SV-UAGA-8X-000167'
  tag stig_id: 'UAGA-8X-000167'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  result = uaghelper.runrestcommand('rest/v1/config/certs/ssl')

  describe result do
    its('status') { should cmp 200 }
  end

  unless result.status != 200
    certinfo = OpenSSL::X509::Certificate.new(result.body)

    allowed = input('allowedCertAuth')

    describe "Validating cert '#{certinfo.subject.to_s(OpenSSL::X509::Name::RFC2253).upcase}' against allowed Issuer list" do
      subject { allowed }
      it { should include certinfo.issuer.to_s(OpenSSL::X509::Name::RFC2253).upcase }
    end
  end
end
