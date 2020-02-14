control "VCLD-67-000029" do
  title "VAMI must disable directory browsing."
  desc  "The goal is to completely control the web user's experience in
navigating any portion of the web document root directories. Ensuring all web
content directories have at least the equivalent of an index.html file is a
significant factor to accomplish this end.

    Enumeration techniques, such as URL parameter manipulation, rely upon being
able to obtain information about the web server's directory structure by
locating directories without default pages. In the scenario, the web server
will display to the user a listing of the files in the directory being
accessed. By having a default hosted application web page, the anonymous web
user will not obtain directory browsing information or an error message that
reveals the server type and version.

  "
  tag component: "vami"
  tag severity: nil
  tag gtitle: "SRG-APP-000266-WSR-000142"
  tag gid: nil
  tag rid: "VCLD-67-000029"
  tag stig_id: "VCLD-67-000029"
  tag cci: "CCI-001312"
  tag nist: ["SI-11 a", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

grep '^dir-listing.activate' /opt/vmware/etc/lighttpd/lighttpd.conf

If the value for \"dir-listing.activate\" is not set to \"disable\", this is a
finding."
  desc 'fix', "Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf

Configure the \"lighttpd.conf\" file with the following:

 dir-listing.activate  = \"disable\""

  describe parse_config_file('/opt/vmware/etc/lighttpd/lighttpd.conf').params['dir-listing.activate'] do
    it { should eq "\"disable\"" }
  end

end

