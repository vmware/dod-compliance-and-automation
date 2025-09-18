control 'NGNX-WB-000101' do
  title 'NGINX must use an approved certificate for SSL/TLS connections.'
  desc  'Class 3 PKI certificates are used for servers and software signing rather than for identifying individuals. Class 4 certificates are used for business-to-business transactions. Utilizing unapproved certificates not issued or approved by DoD or CNS creates an integrity risk. The application server must utilize approved DoD or CNS Class 3 or Class 4 certificates for software signing and business-to-business transactions.'
  desc  'rationale', ''
  desc  'check', "
    Verify the web server is configured to use an approve certificate for SSL/TLS connections.

    Navigate to the web site or sites hosted by NGINX and inspect the certificates presented.

    If any site served by NGINX is not using a certificate issued by an approved certificate authority, this is a finding.
  "
  desc 'fix', "
    Obtain a suitable certificate from an approved certificate authority before proceeding with the below steps.

    Navigate to and open:

    The nginx.conf (/etc/nginx/nginx.conf by default or the included file where the server block for the web site is defined) file.

    Add or update the \"ssl_certificate\" and \"ssl_certificate_key\" directives, for example:

    server {
      ssl_certificate /etc/nginx/ssl/certificate.pem;
      ssl_certificate_key /etc/nginx/ssl/certificate.key;
    }

    Note: Update the certificate path and names as needed.

    Reload the NGINX configuration by running the following command:

    # nginx -s reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'NGNX-WB-000101'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  nginx_cert_issuer = input('nginx_cert_issuer')
  servers = nginx_conf_custom(input('nginx_conf_path')).servers

  servers.each do |server|
    cert = server.params['ssl_certificate']
    if cert
      cert = cert.flatten
      describe x509_certificate(cert[0]) do
        its('issuer.CN') { should match(/#{nginx_cert_issuer}/) }
      end
    else
      describe cert do
        it { should_not be nil }
      end
    end
  end
end
