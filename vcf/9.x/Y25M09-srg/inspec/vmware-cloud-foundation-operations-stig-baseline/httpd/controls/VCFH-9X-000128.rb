control 'VCFH-9X-000128' do
  title 'The VMware Cloud Foundation Operations Apache HTTP service must configure the Referrer-Policy header.'
  desc  "A Referrer header may expose sensitive data in another web server's log if you use sensitive data in your URL parameters, such as personal information, username, and password or persistent sessions. Ultimately, depending on your application design, not using a properly configured Referrer Policy may allow session hijacking, credential gathering, or sensitive data exposure in a third party's logs."
  desc  'rationale', ''
  desc  'check', "
    Verify a header is present to configure Referrer-Policy.

    Note: any Header set at the \"<VirtualHost>\" level will override any root level setting.

    At the command prompt, run the following command to check for a root level setting:

    # awk '/^<[^\\/]/ { depth++; next } /^<\\// { depth--; next } depth == 0 { print }' /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf | grep -i 'Referrer-Policy'

    At the command prompt, run the following command to check for a \"<VirtualHost *:443>\" level setting:

    # sed -n \"/<VirtualHost\\s\\*:443>/,/<\\/VirtualHost>/p\" /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf | grep -i 'Referrer-Policy'

    Example output:

    Header set Referrer-Policy \"same-origin\"

    If a header directive is not present at either the root level or the \"<VirtualHost *:443>\" level to configure \"Referrer-Policy\" with either \"same-origin\" or \"no-referrer\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf

    Add or update the following line before the <Location \"/ui\"> block, ensuring the entry is at the root level and not contained within any blocks.

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

  # Check for an entry at the root level of the conf file
  root_header = command("awk '/^<[^\\/]/ { depth++; next } /^<\\// { depth--; next } depth == 0 { print }' #{conf} | grep -i 'Referrer-Policy'").stdout.strip

  # Check for an entry in the <VirtualHost> section
  vhost_header = command("sed -n \"/<VirtualHost\\s\\*:443>/,/<\\/VirtualHost>/p\" #{conf} | grep -i 'Referrer-Policy'").stdout.strip

  # If an entry is found at the vhost level, use it, otherwise use the root value
  header = vhost_header.empty? ? root_header : vhost_header

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
