control 'VCFQ-9X-000010' do
  title 'The VMware Cloud Foundation Operations Fleet Management NGINX server must produce log records containing sufficient information to establish what type of events occurred.'
  desc  "
    Web server logging capability is critical for accurate forensic analysis. Without sufficient and accurate information, a correct replay of the events cannot be determined.

    Ascertaining the correct type of event that occurred is important during forensic analysis. The correct determination of the event and when it occurred is important in relation to other events that happened at that same time.

    Without sufficient information establishing what type of log event occurred, investigation into the cause of event is severely hindered. Log record content that may be necessary to satisfy the requirement of this control includes, but is not limited to, time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application-specific events, success/fail indications, file names involved, access control, or flow control rules invoked.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the log format has been enabled in the http context.

    View the running configuration by running the following command:

    # nginx -T

    Example configuration:

    http {
      log_format main '$remote_addr - $remote_user [$time_local] \"$request\" $status $body_bytes_sent \"$http_referer\" \"$http_user_agent\" \"$http_x_forwarded_for\"';
    }

    If the log_format directive is not configured in the http context and contain at least the variables shown in the example, this is a finding.

    Note: \"$time_iso8601\" is also acceptable instead of \"$time_local\".
  "
  desc 'fix', "
    Navigate to and open:

    The nginx.conf (/etc/nginx/nginx.conf by default) file.

    Add the following or similar in the http context:

    log_format main '$remote_addr - $remote_user [$time_local] \"$request\" $status $body_bytes_sent \"$http_referer\" \"$http_user_agent\" \"$http_x_forwarded_for\"';

    Reload the NGINX configuration by running the following command:

    # nginx -s reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000095-WSR-000056'
  tag satisfies: ['SRG-APP-000096-WSR-000057', 'SRG-APP-000097-WSR-000058', 'SRG-APP-000098-WSR-000059', 'SRG-APP-000098-WSR-000060', 'SRG-APP-000099-WSR-000061', 'SRG-APP-000100-WSR-000064', 'SRG-APP-000375-WSR-000171']
  tag gid: 'V-VCFQ-9X-000010'
  tag rid: 'SV-VCFQ-9X-000010'
  tag stig_id: 'VCFQ-9X-000010'
  tag cci: ['CCI-000130', 'CCI-000131', 'CCI-000132', 'CCI-000133', 'CCI-000134', 'CCI-001487', 'CCI-001889']
  tag nist: ['AU-3 a', 'AU-3 b', 'AU-3 c', 'AU-3 d', 'AU-3 e', 'AU-3 f', 'AU-8 b']

  log_format = nginx_conf_custom(input('nginx_conf_path')).params['http'][0]['log_format']
  nginx_access_log_format_name = input('nginx_access_log_format_name')

  if log_format
    log_format = log_format.flatten.inspect
    describe 'The log_format directive in the http context' do
      subject { log_format }
      it { should match(/\$remote_addr/) }
      it { should match(/\$remote_user/) }
      it { should match(/\$time_local|\$time_iso8601/) }
      it { should match(/\$request/) }
      it { should match(/\$status/) }
      it { should match(/\$body_bytes_sent/) }
      it { should match(/\$http_referer/) }
      it { should match(/\$http_user_agent/) }
      it { should match(/\$http_x_forwarded_for/) }
      it { should match(/#{nginx_access_log_format_name}/) }
    end
  else
    describe log_format do
      it { should_not be nil }
    end
  end
end
