control 'VRPE-8X-000001' do
  title 'The VMware Aria Operations Apache server must limit the number of allowed simultaneous session requests.'
  desc  'Resource exhaustion can occur when an unlimited number of concurrent requests are allowed on a web site  facilitating a denial of service attack. Mitigating this kind of attack will include limiting the number of concurrent HTTP/HTTPS requests per IP address and may include where feasible limiting parameter values associated with keepalive (i.e., a parameter used to limit the amount of time a connection may be inactive).'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # grep MaxKeepAliveRequests /etc/httpd/httpd.conf | grep -v '^#'

    Example result:

    MaxKeepAliveRequests 100

    If the command does not produce any output, this is not a finding.

    If the output does not match the expected value defined for the environment, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf

    Add or configure the following line:

    MaxKeepAliveRequests 100

    At the command prompt, run the following command:

    # systemctl restart httpd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000001-WSR-000001'
  tag gid: 'V-VRPE-8X-000001'
  tag rid: 'SV-VRPE-8X-000001'
  tag stig_id: 'VRPE-8X-000001'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']

  # Default value is 100, so if setting does not exist, control should still pass
  input('apacheConfFiles').each do |conf|
    next if apache_conf(conf).MaxKeepAliveRequests.nil?
    describe apache_conf(conf) do
      its('MaxKeepAliveRequests') { should cmp input('maxKeepAliveRequests') }
    end
  end
end
