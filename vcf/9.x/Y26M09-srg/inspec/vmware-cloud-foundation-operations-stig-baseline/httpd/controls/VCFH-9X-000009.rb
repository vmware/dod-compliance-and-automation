control 'VCFH-9X-000009' do
  title 'The VMware Cloud Foundation Operations Apache HTTP service must produce log records containing sufficient information to establish what type of events occurred.'
  desc  "
    Web server logging capability is critical for accurate forensic analysis. Without sufficient and accurate information, a correct replay of the events cannot be determined.

    For web servers, events logging includes, but is not limited to, the detection of the following:
    •\tXSS attacks (detect in server, mproxy, and WAF types logs).
    •\tCross Site Request Forgery attacks.
    •\tWeb Cache Poisoning.
    •\tInstances of Session Hijacking.
    •\tInstances of Server Side Request Forgery.

    Ascertaining the correct type of event that occurred is important during forensic analysis. The correct determination of the event and when it occurred is important in relation to other events that happened at that same time.

    Without sufficient information establishing what type of log event occurred, investigation into the cause of event is severely hindered. Log record content that may be necessary to satisfy the requirement of this control includes, but is not limited to, time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application-specific events, success/fail indications, file names involved, access control, or flow control rules invoked.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify that error logs are enabled and logging at a level to produce log records with sufficient information.

    At the command prompt, run the following:

    # grep -i -E \"ErrorLog|LogLevel\" /etc/httpd/conf/httpd.conf

    Example output:

    ErrorLog \"/var/log/httpd/error_log\"
    LogLevel info

    If the value of \"ErrorLog\" is not configured to \"/var/log/httpd/error_log\", this is a finding.

    If the value of \"LogLevel\" is not configured to \"info\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/httpd/conf/httpd.conf

    Add or update the following lines:

    ErrorLog \"/var/log/httpd/error_log\"
    LogLevel info

    Reload the configuration by running the following command:

    # systemctl reload httpd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000095-WSR-000056'
  tag gid: 'V-VCFH-9X-000009'
  tag rid: 'SV-VCFH-9X-000009'
  tag stig_id: 'VCFH-9X-000009'
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']

  conf = input('apache_httpd_conf_file')
  apache_error_log = input('apache_error_log')

  # Make sure the conf file exists so the tests do not pass with false positives
  describe file(conf) do
    it { should exist }
  end
  if apache_conf_custom(conf).ErrorLog.nil?
    describe 'ErrorLog' do
      subject { apache_conf_custom(conf).ErrorLog }
      it { should_not be nil }
    end
  else
    describe "#{input('apache_httpd_conf_file')} ErrorLog" do
      subject { apache_conf_custom(conf).ErrorLog.to_s }
      it { should include apache_error_log }
    end
  end
  if apache_conf_custom(conf).LogLevel.nil?
    describe 'LogLevel' do
      subject { apache_conf(conf).LogLevel }
      it { should_not be nil }
    end
  else
    describe apache_conf_custom(conf) do
      its('LogLevel') { should cmp 'info' }
    end
  end
end
