control 'CDAP-10-000121' do
  title 'Cloud Director must use DoD-approved certificates.'
  desc  'Class 3 PKI certificates are used for servers and software signing rather than for identifying individuals. Class 4 certificates are used for business-to-business transactions. Utilizing unapproved certificates not issued or approved by DoD or CNS creates an integrity risk. The application server must utilize approved DoD or CNS Class 3 or Class 4 certificates for software signing and business-to-business transactions.'
  desc  'rationale', ''
  desc  'check', "
    Navigate to the Cloud Director web interface.

    Inspect the site certificate through the browser.

    If the \"Issuer\" of the server certificate is not a DoD certificate authority, this is a finding.
  "
  desc 'fix', "
    Cloud Director has certificates for the HTTPS and Console Proxy endpoints. These can be replaced individually or share a certificate.

    Obtain a web server SSL certificate and private key from an appropriate DoD certificate authority.

    Construct a concatenated PEM file consisting of the issued certificate, intermediate cert(s) and root cert in that order.

    Copy the new certificate(s) and key file(s) to the primary cloud director appliance to the /opt/vmware/vcloud-director/data/transfer folder.

    Update permissions on the files by running the following command(s) for each file:

    # chown vcloud:vcloud <filename>
    # chmod 600 <filename>

    Apply the new certificate by running the following commands:

    # /opt/vmware/vcloud-director/bin/cell-management-tool certificates -j --cert /opt/vmware/vcloud-director/data/transfer/newcert.pem --key /opt/vmware/vcloud-director/data/transfer/newkey.pem --key-password <key password>
    # /opt/vmware/vcloud-director/bin/cell-management-tool certificates -p --cert /opt/vmware/vcloud-director/data/transfer/newcert.pem --key /opt/vmware/vcloud-director/data/transfer/newkey.pem --key-password <key password>

    Stop and start the VCD service by running the following commands:

    # /opt/vmware/vcloud-director/bin/cell-management-tool cell -i $(service vmware-vcd pid cell) -s
    # systemctl start vmware-vcd

    Repeat the preceding steps for each cell remaining.

    If a load balancer or proxy is configured for VCD then an additional step must be taken to update the Public Addresses settings.

    From the Cloud Director provider interface, go to Administration >> Settings >> Public Addresses.

    For the Web Portal, API, and Console Proxy edit the base URLs if needed and upload the new certificate including the chain for each endpoint and Save.

    Note: The steps listed in the fix assume a multi-cell environment with a single certificate with appropriate subject alternative names for each cell.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000514-AS-000137'
  tag gid: 'V-CDAP-10-000121'
  tag rid: 'SV-CDAP-10-000121'
  tag stig_id: 'CDAP-10-000121'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']

  describe ssl_certificate(host: "#{input('vcdURL')}", port: 443) do
    its('issuer_organization') { should cmp 'U.S. Government' }
  end
end
