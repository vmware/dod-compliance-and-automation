control 'VCFH-9X-000101' do
  title 'The VMware Cloud Foundation Operations Apache HTTP service must implement HTTP Strict Transport Security (HSTS) to protect the integrity of remote sessions.'
  desc  'HTTP Strict Transport Security (HSTS) instructs web browsers to only use secure connections for all future requests when communicating with a web site. Doing so helps prevent SSL protocol attacks, SSL stripping, cookie hijacking, and other attempts to circumvent SSL protection.'
  desc  'rationale', ''
  desc  'check', "
    Verify a header is present to configure HSTS.

    At the command prompt, run the following:

    # cat /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf | sed -n \"/^<VirtualHost\\s\\*:443>/,/<\\/VirtualHost>/p\" | grep -i \"Header\"

    Example output:

    Header set Strict-Transport-Security \"max-age=31536000 ; includeSubDomains\"

    If a header directive is not present to configure \"Strict-Transport-Security\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf

    Find the \"VirtualHost\" section listening on port 443 and add or update the following line:

    Header set Strict-Transport-Security \"max-age=31536000 ; includeSubDomains\"

    Reload the configuration by running the following command:

    # systemctl reload httpd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag gid: 'V-VCFH-9X-000101'
  tag rid: 'SV-VCFH-9X-000101'
  tag stig_id: 'VCFH-9X-000101'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  conf = input('apache_virtualhost_conf_file')
  apache_header_hsts = input('apache_header_hsts')

  # Make sure the conf file exists so the tests do not pass with false positives
  describe file(conf) do
    it { should exist }
  end

  header = command("cat #{conf} | sed -n \"/^<VirtualHost\\s\\*:443>/,/<\\/VirtualHost>/p\" | grep -i \"Header\" | grep -i \"Strict-Transport-Security\"").stdout.strip

  if !header.empty?
    describe 'The HSTS header' do
      subject { header }
      it { should cmp apache_header_hsts }
    end
  else
    describe 'The HSTS header' do
      subject { header }
      it { should_not be_empty }
    end
  end
end
