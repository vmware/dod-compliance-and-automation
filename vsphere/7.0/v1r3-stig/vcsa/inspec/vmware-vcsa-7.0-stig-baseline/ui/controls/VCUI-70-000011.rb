control 'VCUI-70-000011' do
  title 'vSphere UI must be configured to limit access to internal packages.'
  desc 'The "package.access" entry in the "catalina.properties" file implements access control at the package level. When properly configured, a Security Exception will be reported if an errant or malicious webapp attempts to access the listed internal classes directly or if a new class is defined under the protected packages.

The vSphere UI comes preconfigured with the appropriate packages defined in "package.access", and this configuration must be maintained.'
  desc 'check', 'At the command prompt, run the following command:

# grep "package.access" /usr/lib/vmware-vsphere-ui/server/conf/catalina.properties

Expected result:

package.access=sun.,org.apache.catalina.,org.apache.coyote.,org.apache.jasper.,org.apache.tomcat.

If the output of the command does not match the expected result, this is a finding.'
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-sso/vmware-sts/conf/catalina.properties

Ensure the "package.access" line is configured as follows:

package.access=sun.,org.apache.catalina.,org.apache.coyote.,org.apache.jasper.,org.apache.tomcat.

Restart the service with the following command:

# vmon-cli --restart vsphere-ui'
  impact 0.5
  tag check_id: 'C-60463r889361_chk'
  tag severity: 'medium'
  tag gid: 'V-256788'
  tag rid: 'SV-256788r889363_rule'
  tag stig_id: 'VCUI-70-000011'
  tag gtitle: 'SRG-APP-000141-WSR-000075'
  tag fix_id: 'F-60406r889362_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe command("grep 'package.access' '#{input('catalinaPropertiesPath')}'") do
    its('stdout.strip') { should eq "#{input('packageAccess')}" }
  end
end
