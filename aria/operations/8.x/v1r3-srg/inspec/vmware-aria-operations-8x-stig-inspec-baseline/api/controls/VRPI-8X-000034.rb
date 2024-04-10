control 'VRPI-8X-000034' do
  title 'The VMware Aria Operations API service must limit privileges for creating or modifying hosted application shared files.'
  desc  "
    Application servers have the ability to specify that the hosted applications utilize shared libraries. The application server must have a capability to divide roles based upon duties wherein one project user (such as a developer) cannot modify the shared library code of another project user. The application server must also be able to specify that non-privileged users cannot modify any shared library code at all.

    Ensuring the Security Lifecycle Listener element is uncommented and sets a minimum Umask value will allow the Tomcat server to perform a number of security checks when starting and prevent the service from starting if they fail.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # xmllint --xpath \"//*[contains(@className, 'SecurityListener')]/parent::*\" /usr/lib/vmware-vcops/tomcat-enterprise/conf/server.xml

    Review to ensure the Security Lifecycle Listener is uncommented and configured correctly based on environment requirements.

    EXAMPLE:
    <Listener className=\"org.apache.catalina.security.SecurityListener\"  minimumUmask=\"0007\" />

    If the \"org.apache.catalina.security.SecurityListener\" listener is not present, this is a finding.

    If the \"org.apache.catalina.security.SecurityListener\" listener is configured with a \"minimumUmask\" and is not \"0007\", this is a finding.
  "
  desc 'fix', "
    Edit the /usr/lib/vmware-vcops/tomcat-enterprise/conf/server.xml file.

    Ensure the Security Lifecycle Listener is uncommented and configured correctly based on environment requirements.

    EXAMPLE:
    <Listener className=\"org.apache.catalina.security.SecurityListener\" />

    Restart the service:
    # systemctl restart api.service

    Note: The default value for \"minimumUmask\" is \"0007\", so it is not mandatory to be present.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000133-AS-000092'
  tag gid: 'V-VRPI-8X-000034'
  tag rid: 'SV-VRPI-8X-000034'
  tag stig_id: 'VRPI-8X-000034'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']

  # Open server.xml file
  xmlconf = xml(input('api-serverXmlPath'))

  describe xmlconf do
    its('Server/Listener/attribute::className') { should include 'org.apache.catalina.security.SecurityListener' }
  end
  describe xmlconf do
    its(["//Listener[@className='org.apache.catalina.security.SecurityListener']/@minimumUmask"]) { should be_in [nil, '0007'] }
  end
end
