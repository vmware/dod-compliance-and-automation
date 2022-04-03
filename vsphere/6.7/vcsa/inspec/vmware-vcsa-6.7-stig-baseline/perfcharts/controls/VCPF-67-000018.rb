control 'VCPF-67-000018' do
  title 'Performance Charts must limit the number of allowed connections.'
  desc  "Limiting the number of established connections to Performance Charts
is a basic denial-of-service protection. Servers where the limit is too high or
unlimited can potentially run out of system resources and negatively affect
system availability."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # xmllint --xpath '/Server/Service/Connector/@acceptCount'
/usr/lib/vmware-perfcharts/tc-instance/conf/server.xml

    Expected result:

    acceptCount=\"300\"

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open /usr/lib/vmware-perfcharts/tc-instance/conf/server.xml.

    Configure the <Connector> node with the following value:

    acceptCount=\"300\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000246-WSR-000149'
  tag gid: 'V-239419'
  tag rid: 'SV-239419r674980_rule'
  tag stig_id: 'VCPF-67-000018'
  tag fix_id: 'F-42611r674979_fix'
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']

  describe xml("#{input('serverXmlPath')}") do
    its(['Server/Service/Connector/@acceptCount']) { should cmp "#{input('acceptCount')}" }
  end
end
