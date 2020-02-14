control "VCLD-67-000005" do
  title "VAMI must generate log records for system startup and shutdown."
  desc  "Logging must be started as soon as possible when a service starts and
when a service is stopped. Many forms of suspicious actions can be
detected by analyzing logs for unexpected service starts and stops.
Also, by starting to log immediately after a service starts, it becomes
more difficult for suspicous activity to go un-logged."
  tag component: "vami"
  tag severity: nil
  tag gtitle: "SRG-APP-000089-WSR-000047"
  tag gid: nil
  tag rid: "VCLD-67-000005"
  tag stig_id: "VCLD-67-000005"
  tag cci: "CCI-000169"
  tag nist: ["AU-12 a", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

egrep 'server\\sstarted|server\\sstopped' /opt/vmware/var/log/lighttpd/error.log

If server stopped and server started times are not listed, this is a finding."
  desc 'fix', "Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf

Configure the \"lighttpd.conf\" file with the following:

server.errorlog = log_root + \"/error.log\""

  describe parse_config_file('/opt/vmware/etc/lighttpd/lighttpd.conf').params['server.errorlog'] do
    it { should eq "log_root + \"/error.log\"" }
  end

end

