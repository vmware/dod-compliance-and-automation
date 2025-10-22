control 'CDAP-10-000127' do
  title 'Cloud Director must use DoD-approved certificates for the appliance management interface.'
  desc  "
    Class 3 PKI certificates are used for servers and software signing rather than for identifying individuals. Class 4 certificates are used for business-to-business transactions. Utilizing unapproved certificates not issued or approved by DoD or CNS creates an integrity risk. The application server must utilize approved DoD or CNS Class 3 or Class 4 certificates for software signing and business-to-business transactions.

    By default, the embedded PostgreSQL database and the VMware Cloud Director appliance management user interface share a set of self-signed SSL certificates. For increased security, you can replace the default self-signed certificates with certificate authority (CA) signed certificates.
  "
  desc  'rationale', ''
  desc  'check', "
    Navigate to the Cloud Director appliance management web interface.

    Inspect the site certificate through the browser.

    If the \"Issuer\" of the server certificate is not a DoD certificate authority, this is a finding.
  "
  desc 'fix', "
    Send the certificate signing request which is located at /opt/vmware/appliance/etc/ssl/vcd_ova.csr to the appropriate DoD certificate authority for signing.

    Copy the new PEM formatted certificate to the cloud director appliance and replace the existing certificate /opt/vmware/appliance/etc/ssl/vcd_ova.crt.

    If you are replacing the certificate for the primary database, place all other nodes into maintenance mode to prevent the possibility of data loss.

    To apply the new certificate, run the following command(s):

    # systemctl restart nginx.service && systemctl restart vcd_ova_ui.service
    # systemctl restart vpostgres.service

    If you are replacing the certificate for the primary database, take all other nodes out of maintenance mode.

    Note: The new certificate is imported to the VMware Cloud Director truststore on other VMware Cloud Director cells the next time the appliance-sync function runs. The operation might take up to 60 seconds.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000514-AS-000137'
  tag gid: 'V-CDAP-10-000127'
  tag rid: 'SV-CDAP-10-000127'
  tag stig_id: 'CDAP-10-000127'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']

  describe ssl_certificate(host: "#{input('vcdURL')}", port: 5480) do
    its('issuer_organization') { should cmp 'U.S. Government' }
  end
end
