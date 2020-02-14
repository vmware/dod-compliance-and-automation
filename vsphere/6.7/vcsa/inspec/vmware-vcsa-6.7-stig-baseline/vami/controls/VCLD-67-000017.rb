control "VCLD-67-000017" do
  title "VAMI must have Multipurpose Internet Mail Extensions (MIME) that
invoke OS shell programs disabled."
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
  tag rid: "VCLD-67-000017"
  tag stig_id: "VCLD-67-000017"
  tag cci: "CCI-000381"
  tag nist: ["CM-7 a", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

cat /opt/vmware/etc/lighttpd/lighttpd.conf | egrep '\".sh\"|\".csh\"'

If the command returns any value, this is a finding."
  desc 'fix', "Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf

Navigate to the mimetype.assign section and remove any lines that reference
\".sh\" or \".csh\"."

  describe command("cat /opt/vmware/etc/lighttpd/lighttpd.conf | awk '/mimetype\.assign/,/\)/'") do
    its ('stdout') { should_not match /".sh"/ }
    its ('stdout') { should_not match /".csh"/ }
  end

end

