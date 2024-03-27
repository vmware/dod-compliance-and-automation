control 'VRLT-8X-000001' do
  title 'The VMware Aria Operations for Logs tc Server must limit the number of maximum concurrent connections permitted.'
  desc  "
    Resource exhaustion can occur when an unlimited number of concurrent requests are allowed on a web site, facilitating a denial of service attack. Unless the number of requests is controlled, the web server can eventually consume enough system resources to cause a system crash.

    Mitigating this kind of attack includes limiting the number of concurrent HTTP/HTTPS requests.  Each incoming request requires a thread for the duration of that request. If more simultaneous requests are received than can be handled by the currently available request processing threads, additional threads will be created up to the value of the \"maxThreads\" attribute.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # xmllint --xpath \"//Connector[not(@executor) and not(@redirectPort) and @maxThreads]/@maxThreads\" /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/server.xml

    If the value of \"maxThreads\" is missing, this is not a finding.

    If the value of \"maxThreads\" is set at a Connector node, and the value is not set to an allowed limit for the environment, this is a finding.

    Note:  If a Connector is linked to an Executor, Executor settings will override Connector settings. In the commands above, the value 200 is default and should be replaced with the appropriate value for the environment.
  "
  desc 'fix', "
    Edit the /usr/lib/loginsight/application/etc/3rd_config/server.xml file.

    Navigate to each applicable <Connector> node that is not a redirect to a secure port, and is not linked to an Executor.

    Configure the <Connector> node with the value 'maxThreads=\"200\"'

    Example:
        <Connector
             ...
             maxThreads=\"200\"
             ...
        />

    Restart the service:
    # systemctl restart loginsight.service

    Note:  If a Connector is linked to an Executor, Executor settings will override Connector settings, and the \"maxThreads\" setting must be configured correctly in the Executor. In the example above, the value 200 is default and should be replaced with the appropriate value for the environment.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000001-AS-000001'
  tag gid: 'V-VRLT-8X-000001'
  tag rid: 'SV-VRLT-8X-000001'
  tag stig_id: 'VRLT-8X-000001'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']

  # Open server.xml file and get the input variable value
  xmlconf = xml("#{input('catalinaBase')}/conf/server.xml")
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
    xmlconf['//Connector/@maxThreads'].each do |conn|
      describe conn do
        it { should cmp mt }
      end
    end
  end
end
