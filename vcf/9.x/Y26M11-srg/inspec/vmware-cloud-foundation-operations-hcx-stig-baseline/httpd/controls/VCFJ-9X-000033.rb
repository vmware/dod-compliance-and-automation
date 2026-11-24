control 'VCFJ-9X-000033' do
  title 'The VMware Cloud Foundation Operations HCX Apache HTTP service must have Web Distributed Authoring (WebDAV) disabled.'
  desc  "
    A web server can be installed with functionality that, just by its nature, is not secure. Web Distributed Authoring (WebDAV) is an extension to the HTTP protocol that, when developed, was meant to allow users to create, change, and move documents on a server, typically a web server or web share. Allowing this functionality, development, and deployment is much easier for web authors.

    WebDAV is not widely used and has serious security concerns because it may allow clients to modify unauthorized files on the web server.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the WebDAV module is not loaded.

    At the command prompt, run the following:

    # httpd -M | grep -i \"dav_module\"

    If the \"dav_module\" is loaded, this is a finding.
  "
  desc 'fix', "
    To remove the WebDAV module, run the following command to find the configuration file that is loading the offending module:

    # grep -i \"dav_module\" /etc/httpd/conf/httpd.conf /opt/vmware/config/apache-httpd/hcx-ssl.conf /opt/vmware/config/apache-httpd/hcx-virtual-hosts.conf

    Example output:

    LoadModule dav_module /usr/lib/httpd/modules/mod_dav.so

    Navigate to and open the target configuration file and comment out the appropriate \"LoadModule\" line.

    Restart the service by running the following command:

    # systemctl restart httpd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000085'
  tag gid: 'V-VCFJ-9X-000033'
  tag rid: 'SV-VCFJ-9X-000033'
  tag stig_id: 'VCFJ-9X-000033'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  conf = input('apache_httpd_conf_file')

  # Make sure the conf file exists so the tests do not pass with false positives
  describe file(conf) do
    it { should exist }
  end
  # Get an array of loaded modules and split on line returns
  modules = command('httpd -M | grep -v "Loaded Modules:"').stdout.split("\n")

  # Interate through each loaded module to see if dav_module is present
  if !modules.nil?
    davmodfound = false
    modules.each do |mod|
      modname = mod.split(' ')[0]
      next unless modname == 'dav_module'
      davmodfound = true
      describe 'The loaded modules list' do
        subject { modname }
        it { should_not cmp 'dav_module' }
      end
    end
    unless davmodfound
      describe 'dav_module found' do
        subject { davmodfound }
        it { should cmp false }
      end
    end
  else
    describe 'No loaded modules found...skipping...' do
      skip 'No loaded modules found...skipping...'
    end
  end
end
