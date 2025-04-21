control 'VCST-70-000002' do
  title 'The Security Token Service must limit the number of concurrent connections permitted.'
  desc 'Resource exhaustion can occur when an unlimited number of concurrent requests are allowed on a website, facilitating a denial-of-service attack. Unless the number of requests is controlled, the web server can consume enough system resources to cause a system crash.

Mitigating this kind of attack will include limiting the number of concurrent HTTP/HTTPS requests. In Tomcat, each incoming request requires a thread for the duration of that request. If more simultaneous requests are received than can be handled by the currently available request processing threads, additional threads will be created up to the value of the "maxThreads" attribute.'
  desc 'check', %q(At the command prompt, run the following command:

# xmllint --xpath '/Server/Service/Executor[@name="tomcatThreadPool"]/@maxThreads' /usr/lib/vmware-sso/vmware-sts/conf/server.xml

Expected result:

maxThreads="150"

If the output does not match the expected result, this is a finding.)
  desc 'fix', %q(Navigate to and open:

/usr/lib/vmware-sso/vmware-sts/conf/server.xml

Navigate to the <Executor> mode with the name of "tomcatThreadPool" and configure with the value 'maxThreads="150"' as follows:

<Executor maxThreads="150" minSpareThreads="50" name="tomcatThreadPool" namePrefix="tomcat-http--" />

Restart the service with the following command:

# vmon-cli --restart sts)
  impact 0.5
  tag check_id: 'C-60421r889206_chk'
  tag severity: 'medium'
  tag gid: 'V-256746'
  tag rid: 'SV-256746r889208_rule'
  tag stig_id: 'VCST-70-000002'
  tag gtitle: 'SRG-APP-000001-WSR-000001'
  tag fix_id: 'F-60364r889207_fix'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']

  describe xml("#{input('serverXmlPath')}") do
    its(['/Server/Service/Executor[@name="tomcatThreadPool"]/@maxThreads']) { should cmp "#{input('maxThreads')}" }
  end
end
