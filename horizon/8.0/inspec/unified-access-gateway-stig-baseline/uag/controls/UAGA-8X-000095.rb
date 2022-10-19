control 'UAGA-8X-000095' do
  title 'The UAG providing user authentication intermediary services using PKI-based user authentication must only accept end entity certificates issued by DoD PKI or DoD-approved PKI Certification Authorities (CAs) for the establishment of protected sessions.'
  desc  "
    Non-DoD approved PKIs have not been evaluated to ensure that they have security controls and identity vetting procedures in place which are sufficient for DoD systems to rely on the identity asserted in the certificate. PKIs lacking sufficient security controls and identity vetting procedures risk being compromised and issuing certificates that enable adversaries to impersonate legitimate users.

    The authoritative list of DoD-approved PKIs is published at http://iase.disa.mil/pki-pke/interoperability. DoD-approved PKI CAs may include Category I, II, and III certificates. Category I DoD-Approved External PKIs are PIV issuers. Category II DoD-Approved External PKIs are Non-Federal Agency PKIs cross certified with the Federal Bridge Certification Authority (FBCA). Category III DoD-Approved External PKIs are Foreign, Allied, or Coalition Partner PKIs.
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
  tag gtitle: 'SRG-NET-000355-ALG-000117'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'UAGA-8X-000095'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']

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
