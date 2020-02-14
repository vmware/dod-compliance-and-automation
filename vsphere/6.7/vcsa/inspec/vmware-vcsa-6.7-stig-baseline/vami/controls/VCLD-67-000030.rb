control "VCLD-67-000030" do
  title "VAMI must not be configured to use mod_status."
  desc  "Any application providing too much information in error logs and in
administrative messages to the screen risks compromising the data and security
of the application and system. The structure and content of error messages
needs to be carefully considered by the organization and development team.

    Lighttpd must only generate error messages that provide information
necessary for corrective actions without revealing sensitive or potentially
harmful information in error logs and administrative messages.  The mod_status
module generates the status overview of the webserver. The information covers:

    uptime
    average throughput
    current throughput
    active connections and their state

    While this information is useful on a development system, production
systems must not have mod_status enabled."
  tag component: "vami"
  tag severity: nil
  tag gtitle: "SRG-APP-000266-WSR-000159"
  tag gid: nil
  tag rid: "VCLD-67-000030"
  tag stig_id: "VCLD-67-000030"
  tag cci: "CCI-001312"
  tag nist: ["SI-11 a", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

/opt/vmware/sbin/vami-lighttpd -p -f
/opt/vmware/etc/lighttpd/lighttpd.conf|grep mod_status

If there is any output, this is a finding."
  desc 'fix', "Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf.

Remove any lines that specify mod_status."

  describe parse_config_file('/opt/vmware/etc/lighttpd/lighttpd.conf').params['mod_status'] do
    it { should eq nil }
  end

end

