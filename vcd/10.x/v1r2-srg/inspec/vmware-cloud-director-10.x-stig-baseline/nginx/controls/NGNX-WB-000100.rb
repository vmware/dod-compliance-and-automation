control 'NGNX-WB-000100' do
  title 'NGINX must not disable keep alive timeouts.'
  desc  "
    The keep alive timeout sets a timeout during which a keep-alive client connection will stay open on the server side.

    Setting a keep alive timeout on the server side helps mitigate denial of service attacks that establish too many persistent connections, exhausting server resources.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the keep alive timeout is not disabled.

    View the running configuration by running the following command:

    # nginx -T 2>&1 | grep \"keepalive_timeout\"

    Example configuration:

    http {
      keepalive_timeout 60s;
    }

    If the the directive \"keepalive_timeout\" is configured and set to 0 or more than the default of 75, this is a finding.

    If the directive \"keepalive_timeout\" is not configured, this is NOT a finding.
  "
  desc 'fix', "
    Navigate to and open:

    The nginx.conf (/etc/nginx/nginx.conf by default or the included file where the directive was configured) file.

    Remove or update the \"keepalive_timeout\" directive to a value > 0 and <= 75, for example:

    keepalive_timeout 60s;

    Reload the NGINX configuration by running the following command:

    # nginx -s reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag gid: 'V-NGNX-WB-000100'
  tag rid: 'SV-NGNX-WB-000100'
  tag stig_id: 'NGNX-WB-000100'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  nginx_keepalive_timeout = input('nginx_keepalive_timeout')
  http_timeout = nginx_conf_custom(input('nginx_conf_path')).params['http'][0]['keepalive_timeout']
  servers = nginx_conf_custom(input('nginx_conf_path')).servers
  locations = nginx_conf_custom(input('nginx_conf_path')).locations

  # Check for setting in HTTP block
  if http_timeout
    http_timeout = http_timeout.flatten.inspect
    describe http_timeout do
      it { should match(/#{nginx_keepalive_timeout}/) }
    end
  else
    describe http_timeout do
      it { should be nil }
    end
  end

  # Check server blocks to ensure setting doesn't exist or configured correctly
  servers.each do |server|
    timeout = server.params['keepalive_timeout']
    if timeout
      describe timeout do
        it { should match(/#{nginx_keepalive_timeout}/) }
      end
    else
      describe timeout do
        it { should be nil }
      end
    end
  end

  # Check location blocks to ensure setting doesn't exist or configured correctly. Leaving out else to keep spam down
  locations.each do |location|
    timeout = location.params['keepalive_timeout']
    next unless timeout
    describe timeout do
      it { should match(/#{nginx_keepalive_timeout}/) }
    end
  end
end
