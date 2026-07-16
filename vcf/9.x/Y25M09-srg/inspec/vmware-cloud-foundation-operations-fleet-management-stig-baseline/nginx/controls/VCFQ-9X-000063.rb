control 'VCFQ-9X-000063' do
  title 'The VMware Cloud Foundation Operations Fleet Management NGINX server must minimize the identity of the web server in information displayed to clients.'
  desc  "
    Information needed by an attacker to begin looking for possible vulnerabilities in a web server includes any information about the web server, backend systems being accessed, and plug-ins or modules being used.

    Web servers will often display error messages to client users displaying enough information to aid in the debugging of the error. The information given back in error messages may display the web server type, version, patches installed, plug-ins and modules installed, type of code being used by the hosted application, and any backends being used for data storage.

    This information could be used by an attacker to blueprint what type of attacks might be successful. The information given to users must be minimized to not aid in the blueprinting of the web server.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify NGINX is configured to minimize the identity of server information displayed to clients.

    View the running configuration by running the following command:

    # nginx -T

    Example configuration:

    http {
      server_tokens off;
    }

    If \"server_tokens\" is not configured to \"off\" in the http context, this is a finding.

    If any server or location contexts configure \"server_tokens\" to \"on\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    The nginx.conf (/etc/nginx/nginx.conf by default) file.

    Add or update the following line in the http context:

    server_tokens off;

    Remove any \"server_token\" lines that are present in server or location contexts.

    Reload the NGINX configuration by running the following command:

    # nginx -s reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000266-WSR-000159'
  tag satisfies: ['SRG-APP-000266-WSR-000160']
  tag gid: 'V-VCFQ-9X-000063'
  tag rid: 'SV-VCFQ-9X-000063'
  tag stig_id: 'VCFQ-9X-000063'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']

  # Check for setting in HTTP block
  describe nginx_conf_custom(input('nginx_conf_path')).params['http'][0]['server_tokens'] do
    it { should include ['off'] }
  end

  # Check server blocks to ensure setting doesn't exist or is off
  servers = nginx_conf_custom(input('nginx_conf_path')).servers

  servers.each do |server|
    describe "Checking server context with listener: #{server.params['listen'].flatten}" do
      subject { server.params['server_tokens'] }
      it { should include(['off']).or be nil }
    end
  end

  # Check location blocks to ensure setting doesn't exist or is off
  locations = nginx_conf_custom(input('nginx_conf_path')).locations

  locations.each do |location|
    describe "Checking location block: #{location.params['_']}" do
      subject { location.params['server_tokens'] }
      it { should include(['off']).or be nil }
    end
  end
end
