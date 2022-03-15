control 'VCUI-67-000002' do
  title 'vSphere UI must limit the number of concurrent connections permitted.'
  desc  "Resource exhaustion can occur when an unlimited number of concurrent
requests are allowed on a website, facilitating a denial-of-service attack.
Unless the number of requests is controlled, the web server can consume enough
system resources to cause a system crash.

    Mitigating this kind of attack will include limiting the number of
concurrent HTTP/HTTPS requests. Each incoming request requires a thread for the
duration of that request. If more simultaneous requests are received than can
be handled by the currently available request processing threads, additional
threads will be created up to the value of the \"maxThreads\" attribute.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --format /usr/lib/vmware-vsphere-ui/server/conf/server.xml | sed
'2 s/xmlns=\".*\"//g' |  xmllint --xpath
'/Server/Service/Connector[@port=\"${http.port}\"]/@maxThreads' -

    Expected result:

    maxThreads=\"800\"

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open /usr/lib/vmware-vsphere-ui/server/conf/server.xml.

    Configure each <Connector> node with the value:

     'maxThreads=\"800\"'

    Example:

    <Connector .. maxThreads=\"800\" ..>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000001-WSR-000001'
  tag gid: 'V-239683'
  tag rid: 'SV-239683r679155_rule'
  tag stig_id: 'VCUI-67-000002'
  tag fix_id: 'F-42875r679154_fix'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']

  describe xml("#{input('serverXmlPath')}") do
    its(['/Server/Service/Connector[@port="${http.port}"]/@maxThreads']) { should cmp "#{input('maxThreads')}" }
  end
end
