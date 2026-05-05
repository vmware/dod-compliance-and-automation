control 'VCFQ-9X-000034' do
  title 'The VMware Cloud Foundation Operations Fleet Management NGINX server must have Web Distributed Authoring (WebDAV) disabled.'
  desc  "
    A web server can be installed with functionality that, just by its nature, is not secure. Web Distributed Authoring (WebDAV) is an extension to the HTTP protocol that, when developed, was meant to allow users to create, change, and move documents on a server, typically a web server or web share. Allowing this functionality, development, and deployment is much easier for web authors.

    WebDAV is not widely used and has serious security concerns because it may allow clients to modify unauthorized files on the web server.
  "
  desc  'rationale', ''
  desc  'check', "
    NGINX modules can be static or dynamic. Static modules are compiled into the NGINX binary and cannot be removed. Dynamic modules must be loaded in the configuration with the \"load_module\" directive to be used.

    Verify NGINX is not compiled with the WebDAV module by running the following command:

    # nginx -V 2>&1 | grep -P 'http_dav_module(?!=dynamic)'

    View the running configuration to verify the WebDAV module is not dynamically loaded by running the following command:

    # nginx -T 2>&1 | grep \"^load_module\"

    Example output:

    load_module modules/ngx_http_dav_module.so;

    If either command returns any output indicating the WebDAV module is present, this is a finding.
  "
  desc 'fix', "
    NGINX does not support removing static modules and must be recompiled without them in order to remove.

    To remove a dynamic module, do the following:

    Navigate to and open:

    The nginx.conf (/etc/nginx/nginx.conf by default) file.

    Remove or comment out the offending \"load_module\" directive, for example:

    # load_module modules/ngx_http_dav_module.so;

    Reload the NGINX configuration by running the following command:

    # nginx -s reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000085'
  tag gid: 'V-VCFQ-9X-000034'
  tag rid: 'SV-VCFQ-9X-000034'
  tag stig_id: 'VCFQ-9X-000034'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  # Check statically compiled modules first
  staticmodules = nginx_custom(input('nginx_bin_path')).modules

  if staticmodules.blank?
    describe 'No modules found.' do
      skip 'No modules found.'
    end
  else
    describe staticmodules do
      it { should_not include 'http_dav' }
    end
  end

  # Check dynamic modules loaded in the nginx config
  dynamicmodules = nginx_conf_custom.params['load_module']

  unless dynamicmodules.blank?
    dynamicmodules = dynamicmodules.flatten
    dynamicmodules.each do |result|
      modname = result.scan(%r{modules/ngx_(\S+)_module\.so}).flatten
      describe modname do
        it { should_not cmp 'http_dav' }
      end
    end
  end
end
