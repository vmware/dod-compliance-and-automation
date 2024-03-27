control 'CFNG-4X-000020' do
  title 'The SDDC Manager NGINX service must prohibit client-side scripts from reading cookie data.'
  desc  'A cookie can be read by client-side scripts easily if cookie properties are not set properly. By allowing cookies to be read by the client-side scripts, information such as session identifiers could be compromised and used by an attacker who intercepts the cookie. Setting cookie properties (i.e. HttpOnly property) to disallow client-side scripts from reading cookies better protects the information inside the cookie.'
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
  tag gtitle: 'SRG-APP-000439-WSR-000154'
  tag satisfies: ['SRG-APP-000439-WSR-000155']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'CFNG-4X-000020'
  tag cci: ['CCI-002418', 'CCI-002418']
  tag nist: ['SC-8', 'SC-8']

  describe nginx_conf_custom(input('nginx_conf_path')).params['http'][0]['proxy_cookie_path'] do
    it { should include ['/', '/; HTTPOnly; Secure'] }
  end
end
