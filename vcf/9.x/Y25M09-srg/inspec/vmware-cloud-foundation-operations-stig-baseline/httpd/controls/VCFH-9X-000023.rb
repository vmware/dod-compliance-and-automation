control 'VCFH-9X-000023' do
  title 'The VMware Cloud Foundation Operations Apache HTTP service must not load modules that have not been fully reviewed, tested, and signed.'
  desc  "
    In the case of a production web server, areas for content development and testing will not exist, as this type of content is only permissible on a development website. The process of developing on a functional production website entails a degree of trial and error and repeated testing. This process is often accomplished in an environment where debugging, sequencing, and formatting of content are the main goals. The opportunity for a malicious user to obtain files that reveal business logic and login schemes is high in this situation. The existence of such immature content on a web server represents a significant security risk that is totally avoidable.

    The web server must enforce, internally or through an external utility, the signing of modules before they are implemented into a production environment. By signing modules, the author guarantees that the module has been reviewed and tested before production implementation.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify only needed and approved modules are loaded.

    At the command prompt, run the following:

    # httpd -M

    Example output:

    Loaded Modules:
     core_module (static)
     so_module (static)
     http_module (static)
     mpm_worker_module (shared)

    If any module is not required for operation, this is a finding.

    Required modules:

    core_module
    so_module
    http_module
    mpm_worker_module
    authn_file_module
    authn_dbm_module
    authn_core_module
    authz_host_module
    authz_groupfile_module
    authz_user_module
    authz_core_module
    access_compat_module
    auth_basic_module
    socache_shmcb_module
    reqtimeout_module
    include_module
    filter_module
    mime_module
    log_config_module
    env_module
    expires_module
    headers_module
    setenvif_module
    version_module
    ssl_module
    unixd_module
    status_module
    autoindex_module
    negotiation_module
    dir_module
    actions_module
    userdir_module
    alias_module
    jk_module
    rewrite_module
    http2_module
    deflate_module
    proxy_module
    proxy_http_module
  "
  desc 'fix', "
    To remove any modules, run the following command, replacing the module name, to find the configuration file that is loading the offending module:

    # grep -i \"<module_name>\" /etc/httpd/conf/httpd.conf /etc/httpd/conf/extra/httpd-ssl.conf /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf

    Example output:

    /etc/httpd/conf/httpd.conf:LoadModule auth_basic_module /usr/lib/httpd/modules/mod_auth_basic.so

    Navigate to and open the target configuration file and comment out the appropriate \"LoadModule\" line.

    Restart the service by running the following command:

    # systemctl restart httpd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000131-WSR-000073'
  tag satisfies: ['SRG-APP-000141-WSR-000075', 'SRG-APP-000141-WSR-000080']
  tag gid: 'V-VCFH-9X-000023'
  tag rid: 'SV-VCFH-9X-000023'
  tag stig_id: 'VCFH-9X-000023'
  tag cci: ['CCI-000381', 'CCI-003992']
  tag nist: ['CM-14', 'CM-7 a']

  conf = input('apache_httpd_conf_file')

  # Make sure the conf file exists so the tests do not pass with false positives
  describe file(conf) do
    it { should exist }
  end

  apache_approved_modules = input('apache_approved_modules')

  # Get an array of loaded modules and split on line returns
  modules = command('httpd -M | grep -v "Loaded Modules:"').stdout.split("\n")

  # Interate through each loaded module to see if ssl_module is present
  if !modules.nil?
    modules.each do |mod|
      modname = mod.split(' ')[0]
      describe "Module: #{modname}" do
        subject { modname }
        it { should be_in apache_approved_modules }
      end
    end
  else
    describe 'No loaded modules found...skipping...' do
      skip 'No loaded modules found...skipping...'
    end
  end
end
