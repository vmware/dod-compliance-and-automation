control 'VRPS-8X-000142' do
  title 'The Casa service default ROOT web application must be removed.'
  desc  'The default ROOT web application includes the version of Tomcat being used, links to Tomcat documentation, examples, FAQs, and mailing lists. The default ROOT web application must be removed from a publicly accessible instance and a more appropriate default page shown to users.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # ls -l $CATALINA_BASE/webapps/ROOT

    If the ROOT web application contains any content, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following command:

    # rm -rf $CATALINA_BASE/webapps/ROOT
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag gid: 'V-VRPS-8X-000142'
  tag rid: 'SV-VRPS-8X-000142'
  tag stig_id: 'VRPS-8X-000142'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe command("ls #{input('casa-tcInstance')}/webapps/ROOT") do
    its('stdout.strip') { should cmp '' }
  end
end
