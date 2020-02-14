control "VCLD-67-000013" do
  title "VAMI log files must only be accessible by privileged users."
  desc  "Log data is essential in the investigation of events. If log data were
to become compromised, then competent forensic analysis and discovery of the
true source of potentially malicious system activity would be difficult, if not
impossible, to achieve. In addition, access to log records provides information
an attacker could potentially use to their advantage since each event record
might contain communication ports, protocols, services, trust relationships,
user names, etc.The web server must protect the log data from unauthorized
read, write, copy, etc. This can be done by the web server if the web server is
also doing the logging function. The web server may also use an external log
system. In either case, the logs must be protected from access by
non-privileged users."
  tag component: "vami"
  tag severity: nil
  tag gtitle: "SRG-APP-000118-WSR-000068"
  tag gid: nil
  tag rid: "VCLD-67-000013"
  tag stig_id: "VCLD-67-000013"
  tag cci: "CCI-000162"
  tag nist: ["AU-9", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

stat -c \"%n permissions are %a\" /opt/vmware/var/log/lighttpd/*.log

If the permissions on each log file are not 640, this is a finding."
  desc 'fix', "At the command prompt, enter the following command:

chmod 640 /opt/vmware/var/log/lighttpd/*.log"

  command('find /opt/vmware/var/log/lighttpd/ -maxdepth 1 -name "*.log"').stdout.split.each do | fname |
    describe file(fname) do
      it { should_not be_more_permissive_than('0640') }
    end
  end

end

