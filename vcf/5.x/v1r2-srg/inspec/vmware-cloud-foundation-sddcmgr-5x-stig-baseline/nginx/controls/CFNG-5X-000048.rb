control 'CFNG-5X-000048' do
  title 'The SDDC Manager NGINX service must have security settings that disallow cookie access outside the originating web server and hosted application.'
  desc  "
    Cookies are used to exchange data between the web server and the client. Cookies, such as a session cookie, may contain session information and user credentials used to maintain a persistent connection between the user and the hosted application since HTTP/HTTPS is a stateless protocol.

    When the cookie parameters are not set properly (i.e., domain and path parameters), cookies can be shared within hosted applications residing on the same web server or to applications hosted on different web servers residing on the same domain.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command:

    # nginx -T 2>&1 | sed -n \"/^http\\s{/,/server\\s{/p\" | grep proxy_cookie_path

    Expected result:

    proxy_cookie_path / \"/; HTTPOnly; Secure\";

    If the output does not match the expected result, this is a finding.
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
  tag gid: 'V-CFNG-5X-000048'
  tag rid: 'SV-CFNG-5X-000048'
  tag stig_id: 'CFNG-5X-000048'
  tag cci: ['CCI-001664', 'CCI-002418']
  tag nist: ['SC-23 (3)', 'SC-8']

  describe nginx_conf_custom(input('nginx_conf_path')).params['http'][0]['proxy_cookie_path'] do
    it { should include ['/', '/; HTTPOnly; Secure'] }
  end
end
