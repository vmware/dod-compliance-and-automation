control 'NGNX-WB-000026' do
  title 'NGINX must only contain modules necessary for operation.'
  desc  "
    A web server can provide many features, services, and processes. Some of these may be deemed unnecessary or too unsecure to run on a production DoD system.

    The web server must provide the capability to disable, uninstall, or deactivate functionality and services that are deemed to be non-essential to the web server mission or can adversely impact server performance.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify NGINX is not complied with unused modules.

    View the running configuration by running the following command:

    # nginx -V

    Example output:

    configure arguments: --prefix=/etc/nginx --sbin-path=/usr/sbin/nginx --conf-path=/etc/nginx/nginx.conf --pid-path=/var/run/nginx.pid --lock-path=/var/run/nginx.lock --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log --add-module=../nginx-njs/njs-0.2.1/nginx --with-http_ssl_module --with-pcre --with-ipv6 --with-stream --with-http_auth_request_module --with-http_sub_module --with-http_stub_status_module --with-http_v2_module

    If any modules specified with the --add-module or --with arguments are not approved, this is a finding.
  "
  desc 'fix', "
    NGINX does not support removing modules if it is not built and installed from source.

    The NGINX configure command is used to create a Makefile to that specifies which modules should be included in the installation.

    Consult the NGINX documentation and recompile the NGINX installation from source without the unneeded modules.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000075'
  tag satisfies: ['SRG-APP-000141-WSR-000080']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'NGNX-WB-000026'
  tag cci: ['CCI-000381', 'CCI-000381']
  tag nist: ['CM-7 a', 'CM-7 a']

  approved_modules = input('approved_modules')

  nginx.modules.each do |result|
    describe result do
      it { should be_in approved_modules }
    end
  end
end
