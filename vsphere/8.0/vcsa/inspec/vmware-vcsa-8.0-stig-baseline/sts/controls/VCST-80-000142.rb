control 'VCST-80-000142' do
  title 'The vCenter STS service default ROOT web application must be removed.'
  desc 'The default ROOT web application includes the version of Tomcat being used, links to Tomcat documentation, examples, FAQs, and mailing lists. The default ROOT web application must be removed from a publicly accessible instance and a more appropriate default page shown to users.'
  desc 'check', 'At the command prompt, run the following command:

# ls -l /var/opt/apache-tomcat/webapps/ROOT

If the ROOT web application contains any content, this is a finding.'
  desc 'fix', 'At the command prompt, run the following command:

# rm -rf /var/opt/apache-tomcat/webapps/ROOT/*'
  impact 0.5
  tag check_id: 'C-62736r934644_chk'
  tag severity: 'medium'
  tag gid: 'V-258996'
  tag rid: 'SV-258996r934646_rule'
  tag stig_id: 'VCST-80-000142'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-62645r934645_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe command("ls #{input('tcCore')}/webapps/ROOT") do
    its('stdout.strip') { should cmp '' }
  end
end
