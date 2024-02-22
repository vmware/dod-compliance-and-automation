control 'VRLT-8X-000142' do
  title 'The VMware Aria Operations for Logs tc Server default ROOT web application must be removed or replaced.'
  desc  'The default ROOT web application includes the version of tc Server that is being used, links to tc Server documentation, examples, FAQs, and mailing lists. The default ROOT web application must be removed from a publicly accessible instance and a more appropriate default page shown to users. It is acceptable to replace the contents of default ROOT with a new default web application.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # ls -l /usr/lib/loginsight/application/3rd_party/apache-tomcat/webapps/ROOT

    Review the index.jsp file. Also review the RELEASE-NOTES.txt file. Look for content that describes the application as being licensed by the Apache Software Foundation. Check the index.jsp for other verbiage that indicates the application is part of the tc Server. Alternatively, use a web browser and access the default web application and determine if the website application in the ROOT folder is provided with the server.

    If the ROOT web application contains tc Server default application content, this is a finding.
  "
  desc 'fix', "
    WARNING: Removing the ROOT folder without replacing the content with valid web based content will result in an error page being displayed to the browser when the browser lands on the default page.

    Either remove the files contained in /usr/lib/loginsight/application/3rd_party/apache-tomcat/webapps/ROOT folder or replace the content of the folder with a new application that serves as the new default server application.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag gid: 'V-VRLT-8X-000142'
  tag rid: 'SV-VRLT-8X-000142'
  tag stig_id: 'VRLT-8X-000142'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe 'Release Notes txt file must not be present in core location' do
    subject { file("#{input('catalinaBase')}/webapps/ROOT/RELEASE-NOTES.txt").exist? }
    it { should eq false }
  end

  describe 'Release Notes txt file must not be present in instance location' do
    subject { file("#{input('catalinaBase')}/webapps/ROOT/RELEASE-NOTES.txt").exist? }
    it { should eq false }
  end

  if file("#{input('catalinaBase')}/webapps/ROOT/index.jsp").exist?
    describe 'Sample content must be removed from core location - checking index.jsp file' do
      subject { file("#{input('catalinaBase')}/webapps/ROOT/index.jsp").content }
      it { should_not include('Tomcat') }
      it { should_not include('Apache') }
    end
  else
    describe 'index.jsp file not found in core location' do
      skip 'sample file not found'
    end
  end

  if file("#{input('catalinaBase')}/webapps/ROOT/index.jsp").exist?
    describe 'Sample content must be removed from instance location - checking index.jsp file' do
      subject { file("#{input('catalinaBase')}/webapps/ROOT/index.jsp").content }
      it { should_not include('Tomcat') }
      it { should_not include('Apache') }
    end
  else
    describe 'index.jsp file not found in instance location' do
      skip 'sample file not found'
    end
  end
end
