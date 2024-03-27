control 'VCPF-80-000138' do
  title 'The vCenter Perfcharts service deployXML attribute must be disabled.'
  desc  "
    The Host element controls deployment. Automatic deployment allows for simpler management but also makes it easier for an attacker to deploy a malicious application. Automatic deployment is controlled by the autoDeploy and deployOnStartup attributes. If both are false, only Contexts defined in server.xml will be deployed, and any changes will require a Tomcat restart.

    In a hosted environment where web applications may not be trusted, set the deployXML attribute to \"false\" to ignore any context.xml packaged with the web application that may try to assign increased privileges to the web application. Note that if the security manager is enabled, the deployXML attribute will default to false.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # xmllint --xpath \"//Host/@deployXML\" /usr/lib/vmware-perfcharts/tc-instance/conf/server.xml

    Expected result:

    deployXML=\"false\"

    If \"deployXML\" does not equal \"false\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-perfcharts/tc-instance/conf/server.xml

    Navigate to the <Host> node and configure with the value \"deployXML=\"false\"\".

    Restart the service with the following command:

    # vmon-cli --restart perfcharts
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag gid: 'V-VCPF-80-000138'
  tag rid: 'SV-VCPF-80-000138'
  tag stig_id: 'VCPF-80-000138'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  # Open server.xml file
  xmlconf = xml(input('serverXmlPath'))

  describe xmlconf do
    its(["name(//Host[not(@deployXML)] | //Host[@deployXML != 'false'])"]) { should cmp [] }
  end
end
