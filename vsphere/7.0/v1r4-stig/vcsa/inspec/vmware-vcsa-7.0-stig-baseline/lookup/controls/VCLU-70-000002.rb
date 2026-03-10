control 'VCLU-70-000002' do
  title 'Lookup Service must limit the number of concurrent connections permitted.'
  desc 'Resource exhaustion can occur when an unlimited number of concurrent requests are allowed on a website, facilitating a denial-of-service attack. Unless the number of requests is controlled, the web server can consume enough system resources to cause a system crash.

Mitigating this kind of attack will include limiting the number of concurrent HTTP/HTTPS requests. Each incoming request requires a thread for the duration of that request. If more simultaneous requests are received than can be handled by the currently available request processing threads, additional threads will be created up to the value of the "maxThreads" attribute.'
  desc 'check', %q(At the command prompt, run the following command:

# xmllint --xpath '/Server/Service/Connector[@port="${bio-custom.http.port}"]/@maxThreads' /usr/lib/vmware-lookupsvc/conf/server.xml

Expected result:

XPath set is empty

If the output does not match the expected result, this is a finding.)
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-lookupsvc/conf/server.xml

In the <Connector> node, remove the "maxThreads" key/value pair.

Restart the service with the following command:

# vmon-cli --restart lookupsvc'
  impact 0.5
  tag check_id: 'C-60382r888710_chk'
  tag severity: 'medium'
  tag gid: 'V-256707'
  tag rid: 'SV-256707r888712_rule'
  tag stig_id: 'VCLU-70-000002'
  tag gtitle: 'SRG-APP-000001-WSR-000001'
  tag fix_id: 'F-60325r888711_fix'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']

  describe xml("#{input('serverXmlPath')}") do
    its(['/Server/Service/Connector[@port="${bio-custom.http.port}"]/@maxThreads']) { should cmp [] }
  end
end
