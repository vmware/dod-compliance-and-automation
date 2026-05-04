control 'VCPF-80-000139' do
  title 'The vCenter Perfcharts service must have Autodeploy disabled.'
  desc 'Tomcat allows auto-deployment of applications while it is running. This can allow untested or malicious applications to be automatically loaded into production. Autodeploy must be disabled in production.'
  desc 'check', 'At the command prompt, run the following command:

# xmllint --xpath "//Host/@autoDeploy" /usr/lib/vmware-perfcharts/tc-instance/conf/server.xml

Expected result:

autoDeploy="false"

If "autoDeploy" does not equal "false", this is a finding.'
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-perfcharts/tc-instance/conf/server.xml

Navigate to the <Host> node and configure with the value "autoDeploy="false"".

Restart the service with the following command:

# vmon-cli --restart perfcharts'
  impact 0.5
  tag check_id: 'C-62835r934941_chk'
  tag severity: 'medium'
  tag gid: 'V-259095'
  tag rid: 'SV-259095r960963_rule'
  tag stig_id: 'VCPF-80-000139'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-62744r934942_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  # Open server.xml file
  xmlconf = xml(input('serverXmlPath'))

  describe xmlconf do
    its(["name(//Host[@autoDeploy != 'false'])"]) { should cmp [] }
  end
end
