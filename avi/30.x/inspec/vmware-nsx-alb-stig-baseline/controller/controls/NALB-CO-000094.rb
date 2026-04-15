control 'NALB-CO-000094' do
  title 'The NSX Advanced Load Balancer Controller must obtain its public key certificates from an approved certificate authority.'
  desc  'For user certificates, each organization obtains certificates from an approved, shared service provider, as required by OMB policy. For federal agencies operating a legacy public key infrastructure cross-certified with the Federal Bridge Certification Authority at medium assurance or higher, this Certification Authority will suffice.'
  desc  'rationale', ''
  desc  'check', "
    Determine if the NSX ALB obtains public key certificates from an appropriate certificate policy through an approved certificate authority.

    From the NSX ALB Controller web interface go to Administration >> System Settings >> Access.

    Note the value in the \"SSL/TLS Certificate\" field then go to Templates >> Security >> SSL/TLS Certificates.

    Review the SSL/TLS Certificate noted in the previous step and it's Issuer.

    If the certificate being used for portal access is not issued by an approved certificate authority, then this is a finding.
  "
  desc 'fix', "
    To update the certificate used for the NSX ALB Controller web interface do the following:

    If an approved certificate has not been imported, from the NSX ALB Controller web interface go to Templates >> Security >> SSL/TLS Certificates.

    Click Create.

    Select either CSR to generate a certificate request to get signed or Import to import a new certificate and click Save.

    Note: To avoid any certificate trust issue, make sure the certificate chain is complete on the NSX ALB Controller and on the client browser. Install the complete certificate chain (the root and the intermediate certificates) on the NSX ALB Controller and on the client browser.

    From the NSX ALB Controller web interface go to Administration >> System Settings.

    Click the edit icon next to \"System Settings\".

    Update the \"SSL/TLS Certificate\" field and select the appropriate certificate imported in the previous steps and click Save.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-NDM-000344'
  tag gid: 'V-NALB-CO-000094'
  tag rid: 'SV-NALB-CO-000094'
  tag stig_id: 'NALB-CO-000094'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe ssl_certificate(host: "#{input('avicontroller')}", port: 443) do
    its('issuer_organization') { should cmp "#{input('portal_cert_issuer_organization')}" }
  end
end
