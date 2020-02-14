control "VCLD-67-000019" do
  title "VAMI must have all mappings to unused and vulnerable scripts to be
removed."
  desc  "Scripts allow server side processing on behalf of the hosted
application user or as processes needed in the implementation of hosted
applications. Removing scripts not needed for application operation or deemed
vulnerable helps to secure the web server. To assure scripts are not added to
the web server and run maliciously, those script mappings that are not needed
or used by the web server for hosted application operation must be removed."
  tag component: "vami"
  tag severity: nil
  tag gtitle: "SRG-APP-000141-WSR-000082"
  tag gid: nil
  tag rid: "VCLD-67-000019"
  tag stig_id: "VCLD-67-000019"
  tag cci: "CCI-000381"
  tag nist: ["CM-7 a", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

cat /opt/vmware/etc/lighttpd/lighttpd.conf | awk '/cgi\\.assign/,/\\)/'

If the output does not exactly match the below expected output, this is a
finding.

cgi.assign                 = ( \".pl\"  => \"/usr/bin/perl\",
                               \".cgi\" => \"/usr/bin/perl\",
                               \".rb\"  => \"/usr/bin/ruby\",
                               \".erb\" => \"/usr/bin/eruby\",
                               \".py\"  => \"/usr/bin/python\" )"
  desc 'fix', "Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf

Navigate to the cgi.assign section and replace it entirely with the following:

cgi.assign                 = ( \".pl\"  => \"/usr/bin/perl\",
                               \".cgi\" => \"/usr/bin/perl\",
                               \".rb\"  => \"/usr/bin/ruby\",
                               \".erb\" => \"/usr/bin/eruby\",
                               \".py\"  => \"/usr/bin/python\" )"

  describe command("cat /opt/vmware/etc/lighttpd/lighttpd.conf | awk '/cgi\.assign/,/\)/'") do
    its ('stdout') { should match "cgi.assign                 = ( \".pl\"  => \"/usr/bin/perl\",\n                               \".cgi\" => \"/usr/bin/perl\",\n                               \".rb\"  => \"/usr/bin/ruby\",\n                               \".erb\" => \"/usr/bin/eruby\",\n                               \".py\"  => \"/usr/bin/python\" )\n" }
  end
                            
end