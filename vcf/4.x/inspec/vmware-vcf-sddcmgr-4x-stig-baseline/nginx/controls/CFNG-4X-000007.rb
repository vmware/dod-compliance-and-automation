control 'CFNG-4X-000007' do
  title 'The SDDC Manager NGINX service must generate information to be used by external applications or entities to monitor and control remote access.'
  desc  'By providing remote access information to an external monitoring system, the organization can monitor for cyber attacks and monitor compliance with remote access policies. The organization can also look at data organization wide and determine an attack or anomaly is occurring on the organization which might not be noticed if the data were kept local to the web server.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command:

    # nginx -T 2>&1 | sed -n \"/^http\\s{/,/server\\s{/p\" | grep log_format

    Expected result:

    log_format custom '$remote_addr - $remote_user [$time_local] \"$request\" $status $body_bytes_sent \"$http_referer\" \"$http_user_agent\" \"$http_x_forwarded_for\"';

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    The nginx.conf (/etc/nginx/nginx.conf by default) file.

    Add the following line in the http context:

    log_format custom '$remote_addr - $remote_user [$time_local] \"$request\" $status $body_bytes_sent \"$http_referer\" \"$http_user_agent\" \"$http_x_forwarded_for\"';

    At the command line, run the following command:

    # nginx -s reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000016-WSR-000005'
  tag satisfies: ['SRG-APP-000095-WSR-000056', 'SRG-APP-000096-WSR-000057', 'SRG-APP-000097-WSR-000058', 'SRG-APP-000098-WSR-000059', 'SRG-APP-000099-WSR-000061', 'SRG-APP-000100-WSR-000064', 'SRG-APP-000375-WSR-000171']
  tag gid: 'V-CFNG-4X-000007'
  tag rid: 'SV-CFNG-4X-000007'
  tag stig_id: 'CFNG-4X-000007'
  tag cci: ['CCI-000067', 'CCI-000130', 'CCI-000131', 'CCI-000132', 'CCI-000133', 'CCI-000134', 'CCI-001487', 'CCI-001889']
  tag nist: ['AC-17 (1)', 'AU-3', 'AU-8 b']

  log_format = nginx_conf_custom(input('nginx_conf_path')).params['http'][0]['log_format']
  nginx_access_log_format_name = input('nginx_access_log_format_name')

  if log_format
    log_format = log_format.flatten.inspect
    describe log_format do
      it { should match(/\$remote_addr/) }
      it { should match(/\$remote_user/) }
      it { should match(/\$time_local/) }
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
