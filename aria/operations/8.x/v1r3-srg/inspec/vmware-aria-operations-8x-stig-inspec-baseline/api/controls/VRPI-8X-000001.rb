control 'VRPI-8X-000001' do
  title 'The VMware Aria Operations API service must limit the number of maximum concurrent connections permitted.'
  desc  "
    Resource exhaustion can occur when an unlimited number of concurrent requests are allowed on a web site, facilitating a denial of service attack. Unless the number of requests is controlled, the web server can eventually consume enough system resources to cause a system crash.

    Mitigating this kind of attack includes limiting the number of concurrent HTTP/HTTPS requests.  Each incoming request requires a thread for the duration of that request. If more simultaneous requests are received than can be handled by the currently available request processing threads, additional threads will be created up to the value of the maxThreads attribute.

    NOTE: Executor settings will override Connector settings
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following commands:

    # xmllint --xpath \"//Executor[not(@maxThreads)]/@name | //Executor[@maxThreads != '200']/@name\" /usr/lib/vmware-vcops/tomcat-enterprise/conf/server.xml | awk 1 RS=' '
    # xmllint --xpath \"//Connector[not(@maxThreads)]/@port | //Connector[@maxThreads != '200']/@port\" /usr/lib/vmware-vcops/tomcat-enterprise/conf/server.xml | awk 1 RS=' '

    The default value for maxThreads is 200.

    If the value of \"maxThreads\" is missing, this is not a finding.

    If the value of \"maxThreads\" is set at either the Executor node or each Connector node, and the value is not set to an allowed limit for the environment, this is a finding.

    Note:  If a Connector is linked to an Executor, Executor settings will override Connector settings. In the commands above, the value 200 is default and should be replaced with the appropriate value for the environment.
  "
  desc 'fix', "
    Navigate to and open /usr/lib/vmware-vcops/tomcat-enterprise/conf/server.xml

    Navigate to the <Executor> node.

    Configure the <Executor> node with the value 'maxThreads=\"200\"'

    Example:
       <Executor maxThreads=\"200\"
              minSpareThreads=\"50\"
              name=\"tomcatThreadPool\"
              namePrefix=\"tomcat-http--\"/>
    <Connector executor=\"tomcatThreadPool\"
       ...>

    Restart the service:
    # systemctl restart api.service

    Note:  If a Connector is linked to an Executor, Executor settings will override Connector settings. In the example above, the value 200 is default and should be replaced with the appropriate value for the environment.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000001-AS-000001'
  tag gid: 'V-VRPI-8X-000001'
  tag rid: 'SV-VRPI-8X-000001'
  tag stig_id: 'VRPI-8X-000001'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']

  # Open server.xml file and get the input variable value
  xmlconf = xml(input('api-serverXmlPath'))
  mt = input('api-maxThreads')

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
