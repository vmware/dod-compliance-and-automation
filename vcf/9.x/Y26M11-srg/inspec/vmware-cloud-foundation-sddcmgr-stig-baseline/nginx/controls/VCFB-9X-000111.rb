control 'VCFB-9X-000111' do
  title 'The VMware Cloud Foundation SDDC Manager NGINX server must enable HTTP/2. '
  desc  "
    HTTP/2, like HTTPS, enhances security compared to HTTP/1.x by minimizing the risk of header-based attacks (e.g., header injection and manipulation).

    Websites that fully utilize HTTP/2 are inherently protected and defend against smuggling attacks. HTTP/2 provides the method for specifying the length of a request, which removes any potential for ambiguity that can be leveraged by an attacker.

    This is applicable to all web architectures such as load balancing/proxy use cases.
    - The front-end and back-end servers should both be configured to use HTTP/2.
    - HTTP/2 must be used for communications between web servers.
    - Browser vendors have agreed to only support HTTP/2 only in HTTPS mode, thus TLS must be configured to meet this requirement. TLS configuration is out of scope for this requirement.
  "
  desc  'rationale', ''
  desc  'check', "
    If a server context does not have \"ssl\" enabled on any listener directives, this is Not Applicable for that server context.

    Verify http2 is enabled for each server context or in the http context.

    View the running configuration by running the following command:

    # nginx -T

    Example configuration:

    server {
      http2 on;
    }

    If the \"http2\" directive is not configured to \"on\" for a server context that has \"ssl\" enabled or is not inherited from the http context, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    The nginx.conf (/etc/nginx/nginx.conf by default or the included file where the server is defined) file.

    Add the \"http2\" directive to the server or http context, for example:

    http2 on;

    Reload the NGINX configuration by running the following command:

    # nginx -s reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000439-WSR-000192'
  tag satisfies: ['SRG-APP-000251-WSR-000194', 'SRG-APP-000251-WSR-000195']
  tag gid: 'V-VCFB-9X-000111'
  tag rid: 'SV-VCFB-9X-000111'
  tag stig_id: 'VCFB-9X-000111'
  tag cci: ['CCI-001310', 'CCI-002418']
  tag nist: ['SC-8', 'SI-10']

  http = nginx_conf_custom(input('nginx_conf_path')).params['http'][0]['http2']
  servers = nginx_conf_custom(input('nginx_conf_path')).servers
  matches = false

  # Check HTTP context. If defined here it should be on. If not here it should be defined in every ssl enabled server context. http2 in the listener directive is deprecated and should be defined on the server or http context
  if http
    describe "Detected 'http2' directive in http context" do
      subject { http }
      it { should cmp 'on' }
    end
    if !servers.empty?
      servers.each do |server|
        next unless server.params['listen'].flatten.include?('ssl')
        matches = true
        describe "Checking server context with listener: #{server.params['listen'].flatten}" do
          subject { server.params['http2'] }
          it { should include(['on']).or be nil }
        end
      end
    else
      describe 'No server contexts...skipping.' do
        skip 'No server contexts...skipping.'
      end
    end
  # Check all SSL enabled server contexts.
  elsif !servers.empty?
    servers.each do |server|
      next unless server.params['listen'].flatten.include?('ssl')
      matches = true
      describe "Checking server context with listener: #{server.params['listen'].flatten}" do
        subject { server.params['http2'] }
        it { should include ['on'] }
      end
    end
  elsif servers.empty?
    describe 'No server contexts...skipping.' do
      skip 'No server contexts...skipping.'
    end
  end
  unless matches
    impact 0.0
    describe 'No listen directives found with ssl enabled.' do
      skip 'No listen directives found with ssl enabled.'
    end
  end
end
