control 'VCFB-9X-000026' do
  title 'The VMware Cloud Foundation SDDC Manager NGINX server must only contain modules necessary for operation.'
  desc  "
    A web server can provide many features, services, and processes. Some of these may be deemed unnecessary or too unsecure to run on a production DOD system.

    The web server must provide the capability to disable, uninstall, or deactivate functionality and services that are deemed to be nonessential to the web server mission or can adversely impact server performance.
  "
  desc  'rationale', ''
  desc  'check', "
    NGINX modules can be static or dynamic. Static modules are compiled into the NGINX binary and cannot be removed. Dynamic modules must be loaded in the configuration with the \"load_module\" directive to be used.

    Verify NGINX is not compiled with unapproved modules.

    View the compiled configuration by running the following command:

    # nginx -V

    Example output:

    configure arguments: --prefix=/etc/nginx --sbin-path=/usr/sbin/nginx --conf-path=/etc/nginx/nginx.conf --pid-path=/var/run/nginx.pid --lock-path=/var/run/nginx.lock --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log --user=nginx --group=nginx --add-dynamic-module=njs-0.8.4/nginx --add-dynamic-module=./headers-more-nginx-module-0.37 --with-pcre --with-compat --with-http_ssl_module --modules-path=/etc/nginx/modules --with-http_auth_request_module --with-http_sub_module --with-http_stub_status_module --with-http_v2_module --with-http_realip_module --with-http_dav_module=dynamic --with-stream=dynamic --with-stream_ssl_preread_module=dynamic

    Review the arguments that match \"--with-<module_name>_module\" for statically compiled modules. This does not include arguments appended with \"=dynamic\".

    View the running configuration by running the following command:

    # nginx -T 2>&1 | grep \"^load_module\"

    Example output:

    load_module modules/ngx_http_js_module.so;

    The following modules are shipped with SDDC Manager and can be considered the approved baseline:

    \"http_ssl\", \"http_auth_request\", \"http_sub\", \"http_stub_status\", \"http_v2\", \"http_realip\"

    If any modules are present that are not in the approved baseline, this is a finding.
  "
  desc 'fix', "
    NGINX does not support removing static modules and must be recompiled without them in order to remove.

    To remove a dynamic module, do the following:

    Navigate to and open:

    The nginx.conf (/etc/nginx/nginx.conf by default) file.

    Remove or comment out the offending \"load_module\" directive, for example:

    # load_module modules/ngx_http_js_module.so;

    Reload the NGINX configuration by running the following command:

    # nginx -s reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000075'
  tag satisfies: ['SRG-APP-000141-WSR-000080']
  tag gid: 'V-VCFB-9X-000026'
  tag rid: 'SV-VCFB-9X-000026'
  tag stig_id: 'VCFB-9X-000026'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  approved_modules = input('approved_modules')

  # Check statically compiled modules first
  staticmodules = nginx_custom(input('nginx_bin_path')).modules

  if staticmodules.blank?
    describe 'No modules found.' do
      skip 'No modules found.'
    end
  else
    staticmodules.each do |result|
      describe result do
        it { should be_in approved_modules }
      end
    end
  end

  # Check dynamic modules loaded in the nginx config
  dynamicmodules = nginx_conf_custom.params['load_module']

  unless dynamicmodules.blank?
    dynamicmodules = dynamicmodules.flatten
    dynamicmodules.each do |result|
      modname = result.scan(%r{modules/ngx_(\S+)_module\.so}).flatten
      describe modname do
        it { should be_in approved_modules }
      end
    end
  end
end
