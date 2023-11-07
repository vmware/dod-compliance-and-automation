control 'VCLU-80-000139' do
  title 'The vCenter Lookup service must have Autodeploy disabled.'
  desc 'Tomcat allows auto-deployment of applications while it is running. This can allow untested or malicious applications to be automatically loaded into production. Autodeploy must be disabled in production.'
  desc 'check', 'At the command prompt, run the following command:

# xmllint --xpath "//Host/@autoDeploy" /usr/lib/vmware-lookupsvc/conf/server.xml

Expected result:

autoDeploy="false"

If "autoDeploy" does not equal "false", this is a finding.'
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-lookupsvc/conf/server.xml

Navigate to the <Host> node and configure with the value "autoDeploy="false"".

Restart the service with the following command:

# vmon-cli --restart lookupsvc'
  impact 0.5
  tag check_id: 'C-62801r934839_chk'
  tag severity: 'medium'
  tag gid: 'V-259061'
  tag rid: 'SV-259061r934841_rule'
  tag stig_id: 'VCLU-80-000139'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-62710r934840_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  # Open server.xml file
  xmlconf = xml(input('serverXmlPath'))

  describe xmlconf do
    its(["name(//Host[@autoDeploy != 'false'])"]) { should cmp [] }
  end
end
