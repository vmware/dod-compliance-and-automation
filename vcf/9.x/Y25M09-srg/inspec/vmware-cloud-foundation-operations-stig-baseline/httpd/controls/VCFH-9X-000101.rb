control 'VCFH-9X-000101' do
  title 'The VMware Cloud Foundation Operations Apache HTTP service must implement HTTP Strict Transport Security (HSTS) to protect the integrity of remote sessions.'
  desc  'HTTP Strict Transport Security (HSTS) instructs web browsers to only use secure connections for all future requests when communicating with a web site. Doing so helps prevent SSL protocol attacks, SSL stripping, cookie hijacking, and other attempts to circumvent SSL protection.'
  desc  'rationale', ''
  desc  'check', "
    Verify a header is present to configure HSTS.

    Note: any Header set at the \"<VirtualHost>\" level will override any root level setting.

    At the command prompt, run the following command to check for a root level setting:

    # awk '/^<[^\\/]/ { depth++; next } /^<\\// { depth--; next } depth == 0 { print }' /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf | grep -i 'Strict-Transport-Security'

    At the command prompt, run the following command to check for a \"<VirtualHost *:443>\" level setting:

    # sed -n \"/<VirtualHost\\s\\*:443>/,/<\\/VirtualHost>/p\" /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf | grep -i 'Strict-Transport-Security'

    Example output:

    Header set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"

    If a header directive is not present at either the root level or the \"<VirtualHost *:443>\" level to configure \"Strict-Transport-Security\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf

    Add or update the following line before the <Location \"/ui\"> block, ensuring the entry is at the root level and not contained within any blocks.

    Header set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"

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

  # Check for an entry at the root level of the conf file
  root_header = command("awk '/^<[^\\/]/ { depth++; next } /^<\\// { depth--; next } depth == 0 { print }' #{conf} | grep -i 'Strict-Transport-Security'").stdout.strip

  # Check for an entry in the <VirtualHost> section
  vhost_header = command("sed -n \"/<VirtualHost\\s\\*:443>/,/<\\/VirtualHost>/p\" #{conf} | grep -i 'Strict-Transport-Security'").stdout.strip

  # If an entry is found at the vhost level, use it, otherwise use the root value
  header = vhost_header.empty? ? root_header : vhost_header

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
