control "VCLD-67-000018" do
  title "VAMI must explicitly disable Multipurpose Internet Mail Extensions
(MIME) mime mappings based on \"Content-Type\"."
  desc  "Controlling what a user of a hosted application can access is part of
the security posture of the web server. Any time a user can access more
functionality than is needed for the operation of the hosted application poses
a security issue. A user with too much access can view information that is not
needed for the user's job role, or the user could use the function in an
unintentional manner.A MIME tells the web server what type of program various
file types and extensions are and what external utilities or programs are
needed to execute the file type."
  tag component: "vami"
  tag severity: nil
  tag gtitle: "SRG-APP-000141-WSR-000081"
  tag gid: nil
  tag rid: "VCLD-67-000018"
  tag stig_id: "VCLD-67-000018"
  tag cci: "CCI-000381"
  tag nist: ["CM-7 a", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

grep \"mimetype.use-xattr\" /opt/vmware/etc/lighttpd/lighttpd.conf

If the mimetype.use-xattr value exists and is sent to anything other than
\"disable\", this is a finding."
  desc 'fix', "Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf

Replace any and all \"mimetype.use-xattr\" lines with the following:

mimetype.use-xattr        = \"disable\""

  describe parse_config_file('/opt/vmware/etc/lighttpd/lighttpd.conf').params['mimetype.use-xattr'] do
    it { should eq "\"disable\"" }
  end

end

