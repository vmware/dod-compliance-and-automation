control 'VCFO-9X-000111' do
  title 'The VMware Cloud Foundation Operations for Networks Platform NGINX server must enable HTTP/2. '
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

    # nginx -T 2>&1 | sed -n '/server\\s{/{:a;N;/.*location/!ba;/listen.*\\sssl/p}' | grep http2

    Example configuration:

    server {
      http2 on;
    }

    If the \"http2\" directive is not configured to \"on\" for a server context that has \"ssl\" enabled or is not inherited from the http context, this is a finding.

    Note: \"http2\" can be defined on the listen directive but this method is deprecated.
  "
  desc 'fix', "
    Navigate to and open:

    The /etc/nginx/sites-available/vnera file.

    Add or update the \"http2\" directive for the server context listening on port 443, for example:

    http2 on;

    Reload the NGINX configuration by running the following command:

    # nginx -s reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000439-WSR-000192'
  tag satisfies: ['SRG-APP-000251-WSR-000194', 'SRG-APP-000251-WSR-000195']
  tag gid: 'V-VCFO-9X-000111'
  tag rid: 'SV-VCFO-9X-000111'
  tag stig_id: 'VCFO-9X-000111'
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
        describe.one do
          describe "Checking SSL enabled server context with listener: #{server.params['listen'].flatten}. The http2 setting" do
            subject { server.params['http2'] }
            it { should include(['on']).or be nil }
          end
          describe "Checking SSL enabled server context with listener: #{server.params['listen'].flatten}. The listener configuration" do
            subject { server.params['listen'].flatten }
            it { should include('http2').or be nil }
          end
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
      describe.one do
        describe "Checking SSL enabled server context with listener: #{server.params['listen'].flatten}. The http2 setting" do
          subject { server.params['http2'] }
          it { should include ['on'] }
        end
        describe "Checking SSL enabled server context with listener: #{server.params['listen'].flatten}. The listener configuration" do
          subject { server.params['listen'].flatten }
          it { should include 'http2' }
        end
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
