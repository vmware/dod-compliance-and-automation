control 'VCFT-9X-000001' do
  title 'The VMware Cloud Foundation Operations for Logs Loginsight service must limit the number of maximum concurrent connections permitted.'
  desc  "
    Resource exhaustion can occur when an unlimited number of concurrent requests are allowed on a web site, facilitating a denial of service attack. Unless the number of requests is controlled, the web server can eventually consume enough system resources to cause a system crash.

    Mitigating this kind of attack includes limiting the number of concurrent HTTP/HTTPS requests.  Each incoming request requires a thread for the duration of that request. If more simultaneous requests are received than can be handled by the currently available request processing threads, additional threads will be created up to the value of the \"maxThreads\" attribute.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following:

    # xmllint --xpath \"//Connector[not(@redirectPort)]/@maxThreads\" /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/server.xml

    Example result:

    maxThreads=\"150\"

    If the value of \"maxThreads\" is not configured to 150, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/loginsight/application/etc/3rd_config/server.xml

    Configure the <Connector> node for port 443 with the property 'maxThreads=\"150\"'.

    Example:
        <Connector
             ...
             maxThreads=\"150\"
             ...
        />

    Restart the service with the following command:

    # systemctl restart loginsight.service

    Note: The configuration in \"/usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/server.xml\" is generated when the service restarts based on the contents of the \"/usr/lib/loginsight/application/etc/3rd_config/server.xml\" file.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000001-AS-000001'
  tag satisfies: ['SRG-APP-000435-AS-000163']
  tag gid: 'V-VCFT-9X-000001'
  tag rid: 'SV-VCFT-9X-000001'
  tag stig_id: 'VCFT-9X-000001'
  tag cci: ['CCI-000054', 'CCI-002385']
  tag nist: ['AC-10', 'SC-5 a']

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
