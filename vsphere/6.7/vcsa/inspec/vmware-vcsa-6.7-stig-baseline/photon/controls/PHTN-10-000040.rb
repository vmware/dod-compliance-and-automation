control "PHTN-10-000040" do
  title "The Photon operating system must configure rsyslog to offload system
logs to a central server."
  desc  "Information stored in one location is vulnerable to accidental or
incidental deletion or alteration. Proper configuration of rsyslog ensures that
information critical to forensic analysis of security events is available for
future action without any manual offloading or cron jobs."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000205-GPOS-00083"
  tag gid: nil
  tag rid: "PHTN-10-000040"
  tag stig_id: "PHTN-10-000040"
  tag cci: "CCI-001312"
  tag nist: ["SI-11 a", "Rev_4"]
  desc 'check', "At the command line, execute the following command:

# cat /etc/vmware-syslog/syslog.conf

The output should be similar to the following:

*.* @<syslog server>:port;RSYSLOG_syslogProtocol23Format

If no line is returned, if the line is commented or no valid syslog server is
specified, this is a finding.

OR

Navigate to https://<hostname>:5480 to access the Virtual Appliance Management
Inferface (VAMI). Authenticate and navigate to \"Syslog Configuration\". If
there is no site-specific syslog server is configured, this is a finding."
  desc 'fix', "Open /etc/vmware-syslog/syslog.conf with a text editor. Remove any
existing content and create a new remote server configuration line:

For UDP

*.* @<syslog server>:port;RSYSLOG_syslogProtocol23Format

For TCP

*.* @@<syslog server>:port;RSYSLOG_syslogProtocol23Format

OR

Navigate to https://<hostname>:5480 to access the Virtual Appliance Management
Inferface (VAMI). Authenticate and navigate to \"Syslog Configuration\". Click
\"Edit\" in the top right. Configure a remote syslog server and click \"OK\"."

  describe file ('/etc/vmware-syslog/syslog.conf') do
    its ('content') { should match /^.*#{input('syslogServer')}.*$/ }
  end

end

