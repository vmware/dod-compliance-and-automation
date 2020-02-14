control "VCST-67-000012" do
  title "The Security Token Service must have Multipurpose Internet Mail
Extensions (MIME) that invoke OS shell programs disabled."
  desc  "MIME mappings tell the Security Token Service what type of program
various file types and extensions are and what external utilities or programs
are needed to execute the file type. By ensuring that various shell
script MIME types are not included in web.xml, the server is protected against
malicious users tricking the server into executing shell command files."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000141-WSR-000081"
  tag gid: nil
  tag rid: "VCST-67-000012"
  tag stig_id: "VCST-67-000012"
  tag cci: "CCI-000381"
  tag nist: ["CM-7 a", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# grep -En '(x-csh<)|(x-sh<)|(x-shar<)|(x-ksh<)'
/usr/lib/vmware-sso/vmware-sts/conf/web.xml

If the command produces any output, this is a finding."
  desc 'fix', "Open /usr/lib/vmware-sso/vmware-sts/conf/web.xml in a text editor.
Remove any and all of the following nodes lines.

<mime-type>application/x-csh</mime-type>
<mime-type>application/x-shar</mime-type>
<mime-type>application/x-sh</mime-type>
<mime-type>application/x-ksh</mime-type>"

  describe command('grep -En \'(x-csh<)|(x-sh<)|(x-shar<)|(x-ksh<)\' /usr/lib/vmware-sso/vmware-sts/conf/web.xml') do
    its ('stdout.strip') { should eq '' }
  end

end