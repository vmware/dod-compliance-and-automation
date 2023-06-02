control 'CFNG-5X-000066' do
  title 'The SDDC Manager NGINX service must set an inactive timeout for proxied sessions.'
  desc  'Leaving sessions open indefinitely is a major security risk. An attacker can easily use an already authenticated session to access the hosted application as the previously authenticated user. By closing sessions after a set period of inactivity, the web server can make certain that those sessions that are not closed through the user logging out of an application are eventually closed.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command:

    # nginx -T 2>&1 | sed -n \"/^http\\s{/,/server\\s{/p\" | grep -E '(proxy_send_timeout)|(proxy_read_timeout)'

    Example result:

    proxy_send_timeout 600;
    proxy_read_timeout 600;

    If the read and send timeout options are not configured in the http context, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    The nginx.conf (/etc/nginx/nginx.conf by default) file.

    Add the following line(s) in the http context:

    proxy_send_timeout 600;
    proxy_read_timeout 600;

    At the command line, run the following command:

    # nginx -s reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000295-WSR-000134'
  tag gid: 'V-CFNG-5X-000066'
  tag rid: 'SV-CFNG-5X-000066'
  tag stig_id: 'CFNG-5X-000066'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']

  nginx_proxy_timeout = input('nginx_proxy_timeout')
  send_timeout = nginx_conf_custom(input('nginx_conf_path')).params['http'][0]['proxy_send_timeout']
  read_timeout = nginx_conf_custom(input('nginx_conf_path')).params['http'][0]['proxy_read_timeout']
  servers = nginx_conf_custom(input('nginx_conf_path')).servers
  locations = nginx_conf_custom(input('nginx_conf_path')).locations

  # Check for setting in HTTP block
  send_timeout = send_timeout.flatten.inspect
  describe send_timeout do
    it { should match(/#{nginx_proxy_timeout}/) }
  end
  read_timeout = read_timeout.flatten.inspect
  describe read_timeout do
    it { should match(/#{nginx_proxy_timeout}/) }
  end

  # Check server blocks to ensure setting doesn't exist or configured correctly
  servers.each do |server|
    sendtimeout = server.params['proxy_send_timeout']
    readtimeout = server.params['proxy_read_timeout']
    if sendtimeout || readtimeout
      describe sendtimeout.flatten.inspect do
        it { should match(/#{nginx_proxy_timeout}/) }
      end
      describe readtimeout.flatten.inspect do
        it { should match(/#{nginx_proxy_timeout}/) }
      end
    else
      describe sendtimeout do
        it { should be nil }
      end
      describe readtimeout do
        it { should be nil }
      end
    end
  end

  # Check location blocks to ensure setting doesn't exist or configured correctly. Leaving out else to keep spam down
  locations.each do |location|
    sendtimeout = location.params['proxy_send_timeout']
    readtimeout = location.params['proxy_read_timeout']
    next unless !sendtimeout.nil? || !readtimeout.nil?
    describe sendtimeout.flatten.inspect do
      it { should match(/#{nginx_proxy_timeout}/) }
    end
    describe readtimeout.flatten.inspect do
      it { should match(/#{nginx_proxy_timeout}/) }
    end
  end
end
