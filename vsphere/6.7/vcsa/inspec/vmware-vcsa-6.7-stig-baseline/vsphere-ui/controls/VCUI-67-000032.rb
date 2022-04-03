control 'V-239713' do
  title 'vSphere UI must restrict its cookie path.'
  desc  "When the cookie parameters are not set properly (i.e., domain and path
parameters), cookies can be shared within hosted applications residing on the
same web server or to applications hosted on different web servers residing on
the same domain.

    vSphere UI is bound to the \"/ui\" virtual path behind the reverse proxy,
and its cookies are configured as such. This configuration must be confirmed
and maintained.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --format /usr/lib/vmware-vsphere-ui/server/conf/context.xml |
xmllint --xpath '/Context/@sessionCookiePath' -

    Expected result:

    sessionCookiePath=\"/ui\"

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open /usr/lib/vmware-vsphere-ui/server/conf/context.xml.

    Add the following configuration to the <Context> node:

    sessionCookiePath=\"/ui\"

    Example:

    <Context useHttpOnly=\"true\" sessionCookieName=\"VSPHERE-UI-JSESSIONID\"
sessionCookiePath=\"/ui\">
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000223-WSR-000011'
  tag gid: 'V-239713'
  tag rid: 'SV-239713r679245_rule'
  tag stig_id: 'VCUI-67-000032'
  tag fix_id: 'F-42905r679244_fix'
  tag cci: ['CCI-001664']
  tag nist: ['SC-23 (3)']

  describe xml("#{input('contextXmlPath')}") do
    its(['/Context/@sessionCookiePath']) { should cmp "#{input('sessionCookiePath')}" }
  end
end
