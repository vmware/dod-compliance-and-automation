control 'VRPI-8X-000142' do
  title 'The VMware Aria Operations API service default ROOT web application must be removed.'
  desc  'The default ROOT web application includes the version of Tomcat being used, links to Tomcat documentation, examples, FAQs, and mailing lists. The default ROOT web application must be removed from a publicly accessible instance and a more appropriate default page shown to users.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # ls -l /usr/lib/vmware-vcops/tomcat-enterprise/webapps/ROOT

    If the ROOT web application contains any content, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following command:

    # rm -rf /usr/lib/vmware-vcops/tomcat-enterprise/webapps/ROOT
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag gid: 'V-VRPI-8X-000142'
  tag rid: 'SV-VRPI-8X-000142'
  tag stig_id: 'VRPI-8X-000142'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe command("ls #{input('api-tcInstance')}/webapps/ROOT") do
    its('stdout.strip') { should cmp '' }
  end
end
