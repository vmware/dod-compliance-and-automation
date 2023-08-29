control 'WOAT-3X-000002' do
  title 'Workspace ONE Access must limit the number of concurrent connections permitted.'
  desc  "
    Resource exhaustion can occur when an unlimited number of concurrent requests are allowed on a web site, facilitating a denial of service attack. Unless the number of requests is controlled, the web server can consume enough system resources to cause a system crash.

    Mitigating this kind of attack will include limiting the number of concurrent HTTP/HTTPS requests. In Tomcat, each incoming request requires a thread for the duration of that request. If more simultaneous requests are received than can be handled by the currently available request processing threads, additional threads will be created up to the value of the maxThreads attribute.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --xpath '/Server/Service/Executor[@name=\"tomcatThreadPool\"]/@maxThreads' /opt/vmware/horizon/workspace/conf/server.xml|sed 's/^ *//'

    Expected result:

    maxThreads=\"300\"

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /opt/vmware/horizon/workspace/conf/server.xml

    Navigate to the <Executor> mode with the name of tomcatThreadPool and configure with the value 'maxThreads=\"300\"'.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000001-WSR-000001'
  tag gid: 'V-WOAT-3X-000002'
  tag rid: 'SV-WOAT-3X-000002'
  tag stig_id: 'WOAT-3X-000002'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']

  describe xml("#{input('serverXmlPath')}") do
    its(['/Server/Service/Executor[@name="tomcatThreadPool"]/@maxThreads']) { should cmp "#{input('maxThreads')}" }
  end
end
