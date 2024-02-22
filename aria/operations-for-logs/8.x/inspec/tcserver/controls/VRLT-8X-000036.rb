control 'VRLT-8X-000036' do
  title 'The VMware Aria Operations for Logs tc Server must disable Stack tracing.'
  desc  'Stack tracing provides debugging information from the application call stacks when a runtime error is encountered. If stack tracing is left enabled, tc Server will provide this call stack information to the requestor which could result in the loss of sensitive information or data that could be used to compromise the system. '
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # xmllint --xpath \"//Connector[@allowTrace]\" /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/server.xml

    If any <Connector ...> data is returned, review each connector element to ensure each connector does not have an \"allowTrace\" setting, or if there, the \"allowTrace\" setting is set to false.

    If any connector element contains the 'allowTrace = \"true\"' statement, this is a finding.
  "
  desc 'fix', "
    Edit the /usr/lib/loginsight/application/etc/3rd_config/server.xml file.

    Remove the 'allow Trace=\"true\"' statement from the affected <Connector ...> nodes.

    Restart the service:
    # systemctl restart loginsight.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag gid: 'V-VRLT-8X-000036'
  tag rid: 'SV-VRLT-8X-000036'
  tag stig_id: 'VRLT-8X-000036'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  # Open server.xml file
  xmlconf = xml("#{input('catalinaBase')}/conf/server.xml")

  # allowTrace either shouldn't be present, or if it is, it should be false
  describe xmlconf do
    its(["//Connector[@allowTrace != 'false']/@port | //Connector[not[@allowTrace]]/@port"]) { should cmp [] }
  end
end
