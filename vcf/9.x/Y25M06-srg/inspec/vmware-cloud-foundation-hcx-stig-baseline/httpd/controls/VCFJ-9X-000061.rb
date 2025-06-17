control 'VCFJ-9X-000061' do
  title 'The VMware Cloud Foundation Operations HCX Apache HTTP service must restrict the ability of users to launch Denial of Service (DoS) attacks against other information systems or networks.'
  desc  "
    A web server can limit the ability of the web server being used in a DoS attack through several methods. The methods employed will depend upon the hosted applications and their resource needs for proper operation.

    An example setting that could be used to limit the ability of the web server being used in a DoS attack is bandwidth throttling.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify a timeout is in place.

    At the command prompt, run the following:

    # grep -i \"Timeout\" /etc/httpd/conf/httpd.conf /opt/vmware/config/apache-httpd/hcx-ssl.conf /opt/vmware/config/apache-httpd/hcx-virtual-hosts.conf

    Example output:

    TimeOut 60

    If the value of \"TimeOut\" is set to 0, this is a finding.

    If \"TimeOut\" does not exist or is commented out, this is not a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/httpd/conf/httpd.conf

    Note: If the offending configuration was found in a different file edit that file instead.

    Remove or update the following lines:

    TimeOut 60

    Reload the configuration by running the following command:

    # systemctl reload httpd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000246-WSR-000149'
  tag satisfies: ['SRG-APP-000435-WSR-000148']
  tag gid: 'V-VCFJ-9X-000061'
  tag rid: 'SV-VCFJ-9X-000061'
  tag stig_id: 'VCFJ-9X-000061'
  tag cci: ['CCI-001094', 'CCI-002385']
  tag nist: ['SC-5 (1)', 'SC-5 a']

  conf = input('apache_httpd_conf_file')

  # Make sure the conf file exists so the tests do not pass with false positives
  describe file(conf) do
    it { should exist }
  end
  if apache_conf_custom(conf).TimeOut.nil?
    describe 'TimeOut' do
      subject { apache_conf_custom(conf).TimeOut }
      it { should be nil }
    end
  else
    describe apache_conf_custom(conf) do
      its('TimeOut') { should_not cmp '0' }
    end
  end
end
