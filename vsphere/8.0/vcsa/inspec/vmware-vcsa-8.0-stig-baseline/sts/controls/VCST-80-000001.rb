control 'VCST-80-000001' do
  title 'The vCenter STS service must limit the number of maximum concurrent connections permitted.'
  desc 'Resource exhaustion can occur when an unlimited number of concurrent requests are allowed on a website, facilitating a denial-of-service attack. Unless the number of requests is controlled, the web server can consume enough system resources to cause a system crash.

Mitigating this kind of attack will include limiting the number of concurrent HTTP/HTTPS requests. In Tomcat, each incoming request requires a thread for the duration of that request. If more simultaneous requests are received than can be handled by the currently available request processing threads, additional threads will be created up to the value of the maxThreads attribute.'
  desc 'check', %q(At the command prompt, run the following command:

# xmllint --xpath '/Server/Service/Executor[@name="tomcatThreadPool"]/@maxThreads' /usr/lib/vmware-sso/vmware-sts/conf/server.xml

Expected result:

maxThreads="150"

If the output does not match the expected result, this is a finding.)
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-sso/vmware-sts/conf/server.xml

Navigate to the <Executor> node with the name of tomcatThreadPool and configure with the value "maxThreads="150"".

Note: The <Executor> node should be configured similar to the following:

<Executor maxThreads="150"
                minSpareThreads="50"
                name="tomcatThreadPool"
                namePrefix="tomcat-http--"/>

Restart the service with the following command:

# vmon-cli --restart sts'
  impact 0.5
  tag check_id: 'C-62710r934566_chk'
  tag severity: 'medium'
  tag gid: 'V-258970'
  tag rid: 'SV-258970r934568_rule'
  tag stig_id: 'VCST-80-000001'
  tag gtitle: 'SRG-APP-000001-AS-000001'
  tag fix_id: 'F-62619r934567_fix'
  tag satisfies: ['SRG-APP-000001-AS-000001', 'SRG-APP-000435-AS-000163']
  tag cci: ['CCI-000054', 'CCI-002385']
  tag nist: ['AC-10', 'SC-5 a']

  # Open server.xml file and get the input variable value
  xmlconf = xml(input('serverXmlPath'))
  mt = input('maxThreads')

  # Does executor exist with a maxThreads?
  if xmlconf['//Executor[@maxThreads]'].count > 0
    # If so, does it have the correct value?
    describe xmlconf do
      its(['//Executor/@maxThreads']) { should cmp [mt] }
    end
    ex_name = xmlconf['//Executor/@name'].join('')
    # Connectors will pass if bound to Executor with a maxThreads
    xmlconf['//Connector/@executor'].each do |conn_ex|
      describe conn_ex do
        it { should cmp ex_name }
      end
    end

    # Check Connectors not bound to Executor
    xmlconf['//Connector[not(@executor)]/@maxThreads'].each do |conn_noex|
      describe conn_noex do
        it { should cmp mt }
      end
    end
  else
    # No Executor with a maxThreads exists - check each connector
    describe xmlconf do
      its(['//Connector/@maxThreads']) { should cmp mt }
    end
  end
end
