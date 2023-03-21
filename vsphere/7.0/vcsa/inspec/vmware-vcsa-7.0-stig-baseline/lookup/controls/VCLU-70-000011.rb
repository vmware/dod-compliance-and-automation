control 'VCLU-70-000011' do
  title 'Lookup Service must be configured to limit access to internal packages.'
  desc  "
    The \"package.access\" entry in the \"catalina.properties\" file implements access control at the package level. When properly configured, a Security Exception will be reported if an errant or malicious webapp attempts to access the listed internal classes directly or if a new class is defined under the protected packages.

    The Lookup Service comes preconfigured with the appropriate packages defined in \"package.access\", and this configuration must be maintained.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # grep \"package.access\" /usr/lib/vmware-lookupsvc/conf/catalina.properties

    Expected result:

    package.access=sun.,org.apache.catalina.,org.apache.coyote.,org.apache.tomcat.,org.apache.jasper.

    If the output of the command does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-sso/vmware-sts/conf/catalina.properties

    Ensure the \"package.access\" line is configured as follows:

    package.access=sun.,org.apache.catalina.,org.apache.coyote.,org.apache.tomcat.,org.apache.jasper.

    Restart the service with the following command:

    # vmon-cli --restart lookupsvc
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000075'
  tag gid: 'V-256716'
  tag rid: 'SV-256716r888739_rule'
  tag stig_id: 'VCLU-70-000011'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe command("grep 'package.access' '#{input('catalinaPropertiesPath')}'") do
    its('stdout.strip') { should eq "#{input('packageAccess')}" }
  end
end
