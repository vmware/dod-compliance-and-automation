control "VCLD-67-000006" do
  title "VAMI must produce log records containing sufficient information to
establish what type of events occurred."
  desc  "After a security incident has occurred, investigators will often
review log files to determine what happened.  Understanding what type of event
occurred is critical for investigation of a susipicous event."
  tag component: "vami"
  tag severity: nil
  tag gtitle: "SRG-APP-000095-WSR-000056"
  tag gid: nil
  tag rid: "VCLD-67-000006"
  tag stig_id: "VCLD-67-000006"
  tag cci: "CCI-000130"
  tag nist: ["AU-3", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

grep \"accesslog.format\" /opt/vmware/etc/lighttpd/lighttpd.conf

The output should be as follows:

# accesslog.format = \"%h %l %u %t \\\"%r\\\" %b %>s \\\"%{User-Agent}i\\\"
\\\"%{Referer}i\\\"\"


The default, commented, accesslog format is acceptable for this requirement. If
the setting is uncommented the format must include '%r' at a minimum. If the
output is not as expected, this is a finding."
  desc 'fix', "Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf

Comment any existing accesslog.format lines by adding a '#' at the beginning of
the line."

  describe.one do
    describe command('grep "accesslog.format" /opt/vmware/etc/lighttpd/lighttpd.conf') do
      its ('stdout.strip') { should match /^# accesslog.format.*$/ }
    end
    describe command('grep "accesslog.format" /opt/vmware/etc/lighttpd/lighttpd.conf') do
      its ('stdout.strip') { should match /^accesslog.format.*%r.*$/ }
    end
  end

end
