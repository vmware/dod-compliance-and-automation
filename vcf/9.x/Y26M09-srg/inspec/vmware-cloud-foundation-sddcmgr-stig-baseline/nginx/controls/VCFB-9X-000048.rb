control 'VCFB-9X-000048' do
  title 'The VMware Cloud Foundation SDDC Manager NGINX server must secure session cookies exchanged between NGINX and the client.'
  desc  "
    Cookies are used to exchange data between the web server and the client. Cookies, such as a session cookie, may contain session information and user credentials used to maintain a persistent connection between the user and the hosted application since HTTP/HTTPS is a stateless protocol.

    When the cookie parameters are not set properly (i.e., domain and path parameters), cookies can be shared within hosted applications residing on the same web server or to applications hosted on different web servers residing on the same domain.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify a header is configured to configure session cookie security. This can be done by specifying the \"HttpOnly\" and \"Secure\" cookie options through the Set-Cookie header or for proxied servers with the \"proxy_cookie_path\" directive.

    View the running configuration by running the following command:

    # nginx -T 2>&1 | sed -n \"/^http\\s{/,/server\\s{/p\" | grep proxy_cookie_path

    Example configuration:

    server {
      add_header Set-Cookie \"Path=/; HttpOnly; Secure\";
    }

    or

    http {
      proxy_cookie_path / \"/; HTTPOnly; Secure\";
    }

    If a \"Set-Cookie\" header is not configured for all servers and locations with the \"HttpOnly\" and \"Secure\" parameters, this is a finding.

    If cookies are alternatively secured with the \"proxy_cookie_path\" directive with the \"HttpOnly\" and \"Secure\" parameters, this is NOT a finding.

    Note: There can be several add_header directives. These directives are inherited from the previous configuration level if and only if there are no add_header directives defined on the current level so care must be taken if add_header is defined at multiple levels to include headers configured at a higher level.
  "
  desc 'fix', "
    Navigate to and open:

    The nginx.conf (/etc/nginx/nginx.conf by default) file.

    Add the following line in the http context:

    proxy_cookie_path / \"/; HTTPOnly; Secure\";

    At the command line, run the following command:

    # nginx -s reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000223-WSR-000011'
  tag satisfies: ['SRG-APP-000439-WSR-000154', 'SRG-APP-000439-WSR-000155']
  tag gid: 'V-VCFB-9X-000048'
  tag rid: 'SV-VCFB-9X-000048'
  tag stig_id: 'VCFB-9X-000048'
  tag cci: ['CCI-001664', 'CCI-002418']
  tag nist: ['SC-23 (3)', 'SC-8']

  describe nginx_conf_custom(input('nginx_conf_path')).params['http'][0]['proxy_cookie_path'] do
    it { should include ['/', '/; HTTPOnly; Secure'] }
  end
end
