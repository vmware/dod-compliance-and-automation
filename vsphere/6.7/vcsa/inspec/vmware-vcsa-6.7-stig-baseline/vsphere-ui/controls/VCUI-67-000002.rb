control "VCUI-67-000002" do
  title "vSphere UI must limit the number of concurrent connections permitted."
  desc  "Resource exhaustion can occur when an unlimited number of concurrent
requests are allowed on a web site, facilitating a denial of service attack.
Unless the number of requests is controlled, the web server can consume enough
system resources to cause a system crash.

    Mitigating this kind of attack will include limiting the number of
concurrent HTTP/HTTPS requests. Each incoming request requires a thread for the
duration of that request. If more simultaneous requests are received than can
be handled by the currently available request processing threads, additional
threads will be created up to the value of the 'maxThreads' attribute."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000266-WSR-000142"
  tag gid: nil
  tag rid: "VCUI-67-000002"
  tag stig_id: "VCUI-67-000002"
  tag cci: "CCI-001312"
  tag nist: ["SI-11 a", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# xmllint --format /usr/lib/vmware-vsphere-ui/server/conf/server.xml | sed '2
s/xmlns=\".*\"//g' |  xmllint --xpath
'/Server/Service/Connector[@port=\"${http.port}\"]/@maxThreads' -

Expected result:

maxThreads=\"800\"

If the output does not match the expected result, this is a finding"
  desc 'fix', "Navigate to and open
/usr/lib/vmware-vsphere-ui/server/conf/server.xml

Configure each <Connector> node with the value 'maxThreads=\"800\"'

Ex:

<Connector .. maxThreads=\"800\" ..>"

  begin
    vcui_conf = xml('/usr/lib/vmware-vsphere-ui/server/conf/server.xml')

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