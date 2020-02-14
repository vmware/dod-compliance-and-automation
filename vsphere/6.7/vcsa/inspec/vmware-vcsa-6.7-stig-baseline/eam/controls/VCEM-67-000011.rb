control "VCEM-67-000011" do
  title "ESX Agent Manager must be configured to limit access to internal
packages."
  desc  "The 'package.access' entry in the catalina.properties file implements
access control at the package level. When properly configured, a Security
Exception will be reported should an errant or malicious webapp attempt to
access the listed internal classes directly, or if a new class is defined under
the protected packages. The ESX Agent Manager comes pre-configured with the
appropriate packages defined in 'package.access' and this configuration must be
maintained."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000141-WSR-000075"
  tag gid: nil
  tag rid: "VCEM-67-000011"
  tag stig_id: "VCEM-67-000011"
  tag cci: "CCI-000381"
  tag nist: ["CM-7 a", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# grep \"package.access\" -A 5 /etc/vmware-eam/catalina.properties

Expected result:

package.access=\\
sun.,\\
org.apache.catalina.,\\
org.apache.coyote.,\\
org.apache.tomcat.,\\
org.apache.jasper.

If the output of the command does not match the expected result, this is a
finding."
  desc 'fix', "Navigate to and open  /etc/vmware-eam/catalina.properties and
ensure that the 'package.access' line is configured as follows:

package.access=\\
sun.,\\
org.apache.catalina.,\\
org.apache.coyote.,\\
org.apache.tomcat.,\\
org.apache.jasper."

  describe command('grep "package.access" -A 5 /etc/vmware-eam/catalina.properties') do
    its ('stdout.strip') { should eq "package.access=\\\nsun.,\\\norg.apache.catalina.,\\\norg.apache.coyote.,\\\norg.apache.tomcat.,\\\norg.apache.jasper." }
  end

end

