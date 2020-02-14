control "VCFL-67-000002" do
  title "vSphere Client must limit the number of concurrent connections
permitted."
  desc  "Resource exhaustion can occur when an unlimited number of concurrent
requests are allowed on a web site, facilitating a denial of service attack.
Unless the number of requests is controlled, the web server can consume enough
system resources to cause a system crash.

    Mitigating this kind of attack will include limiting the number of
concurrent HTTP/HTTPS requests. In Virgo, each incoming request requires a
thread for the duration of that request. If more simultaneous requests are
received than can be handled by the currently available request processing
threads, additional threads will be created up to the value of the maxThreads
attribute."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000001-WSR-000001"
  tag gid: nil
  tag rid: "VCFL-67-000002"
  tag stig_id: "VCFL-67-000002"
  tag cci: "CCI-000054"
  tag nist: ["AC-10", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# xmllint --format --xpath '/Server/Service/Connector/@maxThreads'
/usr/lib/vmware-vsphere-client/server/configuration/tomcat-server.xml

Expected result:

maxThreads=\"800\" maxThreads=\"800\"

If the output does not match the expected result, this is a finding."
  desc 'fix', "Navigate to and open
/usr/lib/vmware-vsphere-client/server/configuration/tomcat-server.xml

Configure each <Connector> node with the following:

maxThreads=\"800\"
"

  begin
    vcui_conf = xml('/usr/lib/vmware-vsphere-client/server/configuration/tomcat-server.xml')

      if vcui_conf['Server/Service/Connector/attribute::maxThreads'].is_a?(Array)
        vcui_conf['Server/Service/Connector/attribute::maxThreads'].each do |x|
          describe x do
            it { should eq "800" }
          end
        end
      else
        describe xml(vcui_conf['Server/Service/Connector/attribute::maxThreads']) do
          it { should eq "800" }
        end
      end
  end

end