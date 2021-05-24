# encoding: UTF-8

control 'VCST-70-000001' do
  title "The Security Token Service must limit the amount of time that each TCP
connection is kept alive."
  desc  "Resource exhaustion can occur when an unlimited number of concurrent
requests are allowed on a website, facilitating a denial of service attack.
Unless the number of requests is controlled, the web server can consume enough
system resources to cause a system crash.

    Mitigating this kind of attack will include limiting the number of
concurrent HTTP/HTTPS requests. In Tomcat, each incoming request requires a
thread for the duration of that request. If more simultaneous requests are
received than can be handled by the currently available request processing
threads, additional threads will be created up to the value of the
\"maxThreads\" attribute.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    #  xmllint --xpath
'/Server/Service/Connector[@port=\"${bio-custom.http.port}\"]/@connectionTimeout'
/usr/lib/vmware-sso/vmware-sts/conf/server.xml

    Expected result:

    connectionTimeout=\"60000\"

    If the output does not match the expected result, this is a finding.
  "
  desc  'fix', "
    Navigate to and open:

    /usr/lib/vmware-sso/vmware-sts/conf/server.xml

    Navigate to each of the <Connector> nodes.

    Configure each <Connector> node with the value:

    connectionTimeout=\"60000\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000001-WSR-000001'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCST-70-000001'
  tag fix_id: nil
  tag cci: 'CCI-000054'
  tag nist: ['AC-10']

  begin
    xmlconf = xml("#{input('serverXmlPath')}")

      if xmlconf['Server/Service/Connector/attribute::connectionTimeout'].is_a?(Array)
        xmlconf['Server/Service/Connector/attribute::connectionTimeout'].each do |x|
          describe x do
            it { should eq "#{input('connectionTimeout')}" }
          end
        end
      else
        describe xml(xmlconf['Server/Service/Connector/attribute::connectionTimeout']) do
          it { should eq "#{input('connectionTimeout')}" }
        end
      end
  end

end

