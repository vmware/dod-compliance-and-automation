# encoding: UTF-8

control 'VCST-70-000012' do
  title "The Security Token Service must have Multipurpose Internet Mail
Extensions (MIME) that invoke operating system shell programs disabled."
  desc  "Resource mapping is the process of tying a particular file type to a
process in the web server that can serve that type of file to a requesting
client and identify which file types are not to be delivered to a client.

    By not specifying which files can and cannot be served to a user, the web
server could deliver to a user web server configuration files, log files,
password files, etc.

    As Tomcat is a Java-based web server, the main file extension used is
*.jsp.  This check ensures that the *.jsp and *.jspx file types have been
properly mapped to servlets.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # grep -En '(x-csh<)|(x-sh<)|(x-shar<)|(x-ksh<)'
/usr/lib/vmware-sso/vmware-sts/conf/web.xml

    If the command produces any output, this is a finding.
  "
  desc  'fix', "
    Navigate to and open:

    /usr/lib/vmware-sso/vmware-sts/conf/web.xml

    Remove any and all of the following nodes lines.

    <mime-type>application/x-csh</mime-type>
    <mime-type>application/x-shar</mime-type>
    <mime-type>application/x-sh</mime-type>
    <mime-type>application/x-ksh</mime-type>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000081'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCST-70-000012'
  tag fix_id: nil
  tag cci: 'CCI-000381'
  tag nist: ['CM-7 a']

  describe command("grep -En \'(x-csh<)|(x-sh<)|(x-shar<)|(x-ksh<)\' '#{input('webXmlPath')}'") do
    its ('stdout.strip') { should eq '' }
  end

end

