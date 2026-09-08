control 'VCFH-9X-000003' do
  title 'The VMware Cloud Foundation Operations Apache HTTP service must use cryptography to protect the integrity of remote sessions.'
  desc  'Data exchanged between the user and the Apache web server can range from static display data to credentials used to log on to the hosted application. Even when data appears to be static, the non-displayed logic in a web page may expose business logic or trusted system relationships. The integrity of all the data being exchanged between the user and the Apache web server must always be trusted. To protect the integrity and trust, encryption methods must be used to protect the complete communication session.'
  desc  'rationale', ''
  desc  'check', "
    Verify the \"ssl_module\" is present.

    At the command prompt, run the following:

    # httpd -M | grep -i \"ssl_module\"

    Example output:

    ssl_module (shared)

    If the \"ssl_module\" is not found, this is a finding.

    Verify that insecure protocols are disabled.

    At the command prompt, run the following:

    # grep -i \"SSLProtocol\" /etc/httpd/conf/httpd.conf /etc/httpd/conf/extra/httpd-ssl.conf /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf

    Example output:

    SSLProtocol +TLSv1.2 +TLSv1.3

    If the value of \"SSLProtocol\" includes anything other than \"+TLSv1.2\" or \"+TLSv1.3\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf

    Note: If the offending configuration was found in a different file edit that file instead.

    Add or update the following lines:

    SSLProtocol +TLSv1.2 +TLSv1.3

    Reload the configuration by running the following command:

    # systemctl reload httpd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000014-WSR-000006'
  tag satisfies: ['SRG-APP-000015-WSR-000014', 'SRG-APP-000033-WSR-000169', 'SRG-APP-000172-WSR-000104', 'SRG-APP-000224-WSR-000139', 'SRG-APP-000427-WSR-000186', 'SRG-APP-000439-WSR-000151', 'SRG-APP-000439-WSR-000152', 'SRG-APP-000439-WSR-000153', 'SRG-APP-000439-WSR-000156', 'SRG-APP-000441-WSR-000181', 'SRG-APP-000442-WSR-000182']
  tag gid: 'V-VCFH-9X-000003'
  tag rid: 'SV-VCFH-9X-000003'
  tag stig_id: 'VCFH-9X-000003'
  tag cci: ['CCI-000068', 'CCI-000197', 'CCI-000213', 'CCI-001188', 'CCI-001453', 'CCI-002418', 'CCI-002420', 'CCI-002422', 'CCI-002470']
  tag nist: ['AC-17 (2)', 'AC-3', 'IA-5 (1) (c)', 'SC-23 (3)', 'SC-23 (5)', 'SC-8', 'SC-8 (2)']

  conf = input('apache_httpd_conf_file')

  # Make sure the conf file exists so the tests do not pass with false positives
  describe file(conf) do
    it { should exist }
  end

  apache_allowed_protocols = input('apache_allowed_protocols')

  # Get an array of loaded modules and split on line returns
  modules = command('httpd -M | grep -v "Loaded Modules:"').stdout.split("\n")

  # Interate through each loaded module to see if ssl_module is present
  if !modules.empty?
    sslmodfound = false
    modules.each do |mod|
      modname = mod.split(' ')[0]
      next unless modname == 'ssl_module'
      sslmodfound = true
      describe 'The loaded modules list' do
        subject { modname }
        it { should cmp 'ssl_module' }
      end
    end
    unless sslmodfound
      describe 'ssl_module found' do
        subject { sslmodfound }
        it { should cmp true }
      end
    end
  else
    describe 'No loaded modules found...skipping...' do
      skip 'No loaded modules found...skipping...'
    end
  end

  # Test to see which SSL Protocols are enabled
  ssl_protocols = apache_conf_custom(conf).SSLProtocol
  if !ssl_protocols.nil?
    ssl_protocols.each do |sslprotocol|
      sslprots = sslprotocol.split
      sslprots.each do |sslprot|
        describe "SSL Protocol: #{sslprot}" do
          subject { sslprot }
          it { should be_in apache_allowed_protocols }
        end
      end
    end
  else
    describe 'SSLProtocol directive' do
      subject { ssl_protocols }
      it { should_not be_nil }
    end
  end
end
