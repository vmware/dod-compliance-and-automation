control "VCUI-67-000010" do
  title "vSphere UI must be configured to limit access to internal packages."
  desc  "The 'package.access' entry in the catalina.properties file implements
access control at the package level. When properly configured, a Security
Exception will be reported should an errant or malicious webapp attempt to
access the listed internal classes directly, or if a new class is defined under
the protected packages. The vSphere UI comes pre-configured with the
appropriate packages defined in 'package.access' and this configuration must be
maintained. "
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000435-WSR-000147"
  tag gid: nil
  tag rid: "VCUI-67-000010"
  tag stig_id: "VCUI-67-000010"
  tag cci: "CCI-002385"
  tag nist: ["SC-5", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# grep \"package.access\"
/usr/lib/vmware-vsphere-ui/server/conf/catalina.properties

Expected result:

package.access=sun.,org.apache.catalina.,org.apache.coyote.,org.apache.jasper.,org.apache.tomcat.

If the output of the command does not match the expected result, this is a
finding."
  desc 'fix', "Navigate to and open
/usr/lib/vmware-sso/vmware-sts/conf/catalina.propertiess and ensure that the
'package.access' line is configured as follows:

package.access=sun.,org.apache.catalina.,org.apache.coyote.,org.apache.jasper.,org.apache.tomcat.
"

  describe parse_config_file('/usr/lib/vmware-vsphere-ui/server/conf/catalina.properties').params['package.access'] do
    it { should eq 'sun.,org.apache.catalina.,org.apache.coyote.,org.apache.jasper.,org.apache.tomcat.' }
  end

end