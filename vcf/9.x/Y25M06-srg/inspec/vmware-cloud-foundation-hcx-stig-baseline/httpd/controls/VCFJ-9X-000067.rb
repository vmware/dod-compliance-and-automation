control 'VCFJ-9X-000067' do
  title 'The VMware Cloud Foundation Operations HCX Apache HTTP service must disable debugging and trace information.'
  desc  'Information needed by an attacker to begin looking for possible vulnerabilities in a web server includes any information about the web server and plug-ins or modules being used. When debugging or trace information is enabled in a production web server, information about the web server, such as web server type, version, patches installed, plug-ins and modules installed, type of code being used by the hosted application, and any backends being used for data storage may be displayed. Since this information may be placed in logs and general messages during normal operation of the web server, an attacker does not need to cause an error condition to gain this information.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following:

    # grep -i \"TraceEnable\" /etc/httpd/conf/httpd.conf /opt/vmware/config/apache-httpd/hcx-ssl.conf /opt/vmware/config/apache-httpd/hcx-virtual-hosts.conf

    Example output:

    TraceEnable Off

    If the value of \"TraceEnable\" is set to \"Extended\", this is a finding.

    If \"TraceEnable\" does not exist or is commented out, this is not a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/httpd/conf/httpd.conf

    Note: If the offending configuration was found in a different file edit that file instead.

    Update or remove the following lines:

    TraceEnable Extended

    Reload the configuration by running the following command:

    # systemctl reload httpd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000266-WSR-000160'
  tag gid: 'V-VCFJ-9X-000067'
  tag rid: 'SV-VCFJ-9X-000067'
  tag stig_id: 'VCFJ-9X-000067'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']

  conf = input('apache_httpd_conf_file')

  # Make sure the conf file exists so the tests do not pass with false positives
  describe file(conf) do
    it { should exist }
  end
  if apache_conf_custom(conf).TraceEnable.nil?
    describe 'TraceEnable' do
      subject { apache_conf_custom(conf).TraceEnable }
      it { should be nil }
    end
  else
    describe apache_conf_custom(conf) do
      its('TraceEnable') { should_not cmp 'Extended' }
    end
  end
end
