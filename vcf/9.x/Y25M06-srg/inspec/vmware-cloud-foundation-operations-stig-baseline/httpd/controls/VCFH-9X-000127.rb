control 'VCFH-9X-000127' do
  title 'The VMware Cloud Foundation Operations Apache HTTP service must enable Content Security Policy.'
  desc  'A Content Security Policy (CSP) requires careful tuning and precise definition of the policy. If enabled, CSP has significant impact on the way browsers render pages (e.g., inline JavaScript is disabled by default and must be explicitly allowed in the policy). CSP prevents a wide range of attacks, including cross-site scripting and other cross-site injections.'
  desc  'rationale', ''
  desc  'check', "
    Verify a header is configured to set Content-Security-Policy.

    At the command prompt, run the following:

    # cat /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf | sed -n \"/^<VirtualHost\\s\\*:443>/,/<\\/VirtualHost>/p\" | grep -i \"Header\"

    Example output:

    Header set Content-Security-Policy \"default-src https: wss: data: 'unsafe-inline' 'unsafe-eval'; child-src *; worker-src 'self' blob:\"

    If a header directive is not present to configure \"Content-Security-Policy\" as shown in the example, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf

    Find the \"VirtualHost\" section listening on port 443 and add or update the following line:

    Header set Content-Security-Policy \"default-src https: wss: data: 'unsafe-inline' 'unsafe-eval'; child-src *; worker-src 'self' blob:\"

    Reload the configuration by running the following command:

    # systemctl reload httpd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag gid: 'V-VCFH-9X-000127'
  tag rid: 'SV-VCFH-9X-000127'
  tag stig_id: 'VCFH-9X-000127'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  conf = input('apache_virtualhost_conf_file')
  apache_header_csp = input('apache_header_csp')

  # Make sure the conf file exists so the tests do not pass with false positives
  describe file(conf) do
    it { should exist }
  end

  header = command("cat #{conf} | sed -n \"/^<VirtualHost\\s\\*:443>/,/<\\/VirtualHost>/p\" | grep -i \"Header\" | grep -i \"Content-Security-Policy\"").stdout.strip

  if !header.empty?
    describe 'The Content-Security-Policy header' do
      subject { header }
      it { should cmp apache_header_csp }
    end
  else
    describe 'The Content-Security-Policy header' do
      subject { header }
      it { should_not be_empty }
    end
  end
end
