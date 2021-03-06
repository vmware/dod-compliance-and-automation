# encoding: UTF-8

control 'VCST-70-000011' do
  title "The Security Token Service must be configured to limit access to
internal packages."
  desc  "MIME mappings tell the Security Token Service what type of program
various file types and extensions are and what external utilities or programs
are needed to execute the file type.

    By ensuring that various shell script MIME types are not included in
\"web.xml\", the server is protected against malicious users tricking the
server into executing shell command files.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # grep \"package.access\"
/usr/lib/vmware-sso/vmware-sts/conf/catalina.properties

    Expected result:


package.access=sun.,org.apache.catalina.,org.apache.coyote.,org.apache.tomcat.,org.apache.jasper.

    If the output of the command does not match the expected result, this is a
finding.
  "
  desc  'fix', "
    Navigate to and open:

    /usr/lib/vmware-sso/vmware-sts/conf/catalina.properties

    Ensure that the \"package.access\" line is configured as follows:


package.access=sun.,org.apache.catalina.,org.apache.coyote.,org.apache.tomcat.,org.apache.jasper.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000075'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCST-70-000011'
  tag fix_id: nil
  tag cci: 'CCI-000381'
  tag nist: ['CM-7 a']

  describe command("grep 'package.access' '#{input('catalinaPropertiesPath')}'") do
    its ('stdout.strip') { should eq "#{input('packageAccess')}" }
  end

end

