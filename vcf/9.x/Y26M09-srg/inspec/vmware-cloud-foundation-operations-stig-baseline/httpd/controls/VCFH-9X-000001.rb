control 'VCFH-9X-000001' do
  title 'The VMware Cloud Foundation Operations Apache HTTP service must limit the number of allowed simultaneous session requests.'
  desc  "
    Web server management includes the ability to control the number of users and user sessions that utilize a web server. Limiting the number of allowed users and sessions per user is helpful in limiting risks related to several types of Denial of Service attacks.

    Although there is some latitude concerning the settings themselves, the settings should follow DoD-recommended values, but the settings should be configurable to allow for future DoD direction. While the DoD will specify recommended values, the values can be adjusted to accommodate the operational requirement of a given system.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the \"KeepAlive\" setting is enabled and that the \"MaxKeepAliveRequests\" is not set to 0, which allows unlimited requests.

    At the command prompt, run the following:

    # grep -i \"KeepAlive\" /etc/httpd/conf/httpd.conf /etc/httpd/conf/extra/httpd-ssl.conf /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf

    Example output:

    KeepAlive On
    MaxKeepAliveRequests 100

    If the value of \"KeepAlive\" is set to \"off\", this is a finding.

    If \"KeepAlive\" does not exist or is commented out, this is not a finding.

    If the value of \"MaxKeepAliveRequests\" is set to 0, this is a finding.

    If \"MaxKeepAliveRequests\" does not exist or is commented out, this is not a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/httpd/conf/httpd.conf

    Note: If the offending configuration was found in a different file edit that file instead.

    Remove or update the following lines:

    KeepAlive On
    MaxKeepAliveRequests 100

    Reload the configuration by running the following command:

    # systemctl reload httpd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000001-WSR-000001'
  tag gid: 'V-VCFH-9X-000001'
  tag rid: 'SV-VCFH-9X-000001'
  tag stig_id: 'VCFH-9X-000001'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']

  # Default value is 100, so if setting does not exist, control should still pass
  conf = input('apache_httpd_conf_file')

  # Make sure the conf file exists so the tests do not pass with false positives
  describe file(conf) do
    it { should exist }
  end
  if apache_conf_custom(conf).MaxKeepAliveRequests.nil?
    describe 'MaxKeepAliveRequests' do
      subject { apache_conf_custom(conf).MaxKeepAliveRequests }
      it { should be nil }
    end
  else
    describe apache_conf_custom(conf) do
      its('MaxKeepAliveRequests') { should_not cmp '0' }
    end
  end
  if apache_conf_custom(conf).KeepAlive.nil?
    describe 'KeepAlive' do
      subject { apache_conf(conf).KeepAlive }
      it { should be nil }
    end
  else
    describe apache_conf_custom(conf) do
      its('KeepAlive') { should cmp 'on' }
    end
  end
end
