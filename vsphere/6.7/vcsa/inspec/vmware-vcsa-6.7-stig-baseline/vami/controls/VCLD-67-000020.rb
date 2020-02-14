control "VCLD-67-000020" do
  title "VAMI must have resource mappings set to disable the serving of certain
file types."
  desc  "Resource mapping is the process of tying a particular file type to a
process in the web server that can serve that type of file to a requesting
client and to identify which file types are not to be delivered to a client.

    By not specifying which files can and which files cannot be served to a
user, the web server could deliver to a user web server configuration files,
log files, password files, etc."
  tag component: "vami"
  tag severity: nil
  tag gtitle: "SRG-APP-000141-WSR-000083"
  tag gid: nil
  tag rid: "VCLD-67-000020"
  tag stig_id: "VCLD-67-000020"
  tag cci: "CCI-000381"
  tag nist: ["CM-7 a", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

grep \"url.access-deny\" /opt/vmware/etc/lighttpd/lighttpd.conf

If the output does not include \"~\" and \".inc\" at a minimum, this is a
finding."
  desc 'fix', "Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf

Navigate to the url.access-deny line and replace it entirely with the following:

url.access-deny             = ( \"~\", \".inc\" )"

  describe parse_config_file('/opt/vmware/etc/lighttpd/lighttpd.conf').params['url.access-deny'] do
    it { should eq '( "~", ".inc" )' }
  end

end

