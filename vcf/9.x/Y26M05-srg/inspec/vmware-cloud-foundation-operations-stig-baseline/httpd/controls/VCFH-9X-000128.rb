control 'VCFH-9X-000128' do
  title 'The VMware Cloud Foundation Operations Apache HTTP service must configure the Referrer-Policy header.'
  desc  "A Referrer header may expose sensitive data in another web server's log if you use sensitive data in your URL parameters, such as personal information, username, and password or persistent sessions. Ultimately, depending on your application design, not using a properly configured Referrer Policy may allow session hijacking, credential gathering, or sensitive data exposure in a third party's logs."
  desc  'rationale', ''
  desc  'check', "
    Verify a header is configured to set Referrer-Policy.

    At the command prompt, run the following:

    # cat /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf | sed -n \"/^<VirtualHost\\s\\*:443>/,/<\\/VirtualHost>/p\" | grep -i \"Header\"

    Example output:

    Header set Referrer-Policy \"no-referrer\"

    If a header directive is not present to configure \"Referrer-Policy\" as shown in the example, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf

    Find the \"VirtualHost\" section listening on port 443 and add or update the following line:

    Header set Referrer-Policy \"no-referrer\"

    Reload the configuration by running the following command:

    # systemctl reload httpd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag gid: 'V-VCFH-9X-000128'
  tag rid: 'SV-VCFH-9X-000128'
  tag stig_id: 'VCFH-9X-000128'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  conf = input('apache_virtualhost_conf_file')
  apache_header_referrer_policy = input('apache_header_referrer_policy')

  # Make sure the conf file exists so the tests do not pass with false positives
  describe file(conf) do
    it { should exist }
  end

  header = command("cat #{conf} | sed -n \"/^<VirtualHost\\s\\*:443>/,/<\\/VirtualHost>/p\" | grep -i \"Header\" | grep -i \"Referrer-Policy\"").stdout.strip

  if !header.empty?
    describe 'The Referrer-Policy header' do
      subject { header }
      it { should cmp apache_header_referrer_policy }
    end
  else
    describe 'The Referrer-Policy header' do
      subject { header }
      it { should_not be_empty }
    end
  end
end
