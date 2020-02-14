control "VCLD-67-000010" do
  title "VAMI must produce log records containing sufficient information to
establish the identity of any user/subject or process associated with an event."
  desc  "After a security incident has occurred, investigators will often
review log files to determine what happened.  VAMI must create a log entry when
a user access the system, and the system the authenticates users.

    The logs must contain information about user sessions to include what type
of event occurred, when (date and time) events occurred, where within the
server the events occurred, the client source of the events, the outcome
(success or failure) of the event, the identity of the user/subject/process
associated with the event."
  tag component: "vami"
  tag severity: nil
  tag gtitle: "SRG-APP-000100-WSR-000064"
  tag gid: nil
  tag rid: "VCLD-67-000010"
  tag stig_id: "VCLD-67-000010"
  tag cci: "CCI-001487"
  tag nist: ["AU-3", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

grep \"accesslog.format\" /opt/vmware/etc/lighttpd/lighttpd.conf

The output should be as follows:

# accesslog.format = \"%h %l %u %t \\\"%r\\\" %b %>s \\\"%{User-Agent}i\\\"
\\\"%{Referer}i\\\"\"


The default, commented, accesslog format is acceptable for this requirement. If
the setting is uncommented the format must include '%u' at a minimum. If the
output is not as expected, this is a finding."
  desc 'fix', "Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf

Comment any existing accesslog.format lines by adding a '#' at the beginning of
the line."

  describe.one do
    describe command('grep "accesslog.format" /opt/vmware/etc/lighttpd/lighttpd.conf') do
      its ('stdout.strip') { should match /^# accesslog.format.*$/ }
    end
    describe command('grep "accesslog.format" /opt/vmware/etc/lighttpd/lighttpd.conf') do
      its ('stdout.strip') { should match /^accesslog.format.*%u.*$/ }
    end
  end

end

