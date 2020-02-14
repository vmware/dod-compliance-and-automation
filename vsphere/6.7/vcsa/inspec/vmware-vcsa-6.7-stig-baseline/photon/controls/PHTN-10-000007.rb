control "PHTN-10-000007" do
  title "The Photon operating system must have sshd authentication logging
enabled."
  desc  "Automated monitoring of remote access sessions allows organizations to
detect cyber attacks and ensure ongoing compliance with remote access policies
by auditing connection activities.

    Shipping sshd authentication events to syslog allows organizations to use
their log aggregators to correlate forensic activities among multiple systems."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000032-GPOS-00013"
  tag gid: nil
  tag rid: "PHTN-10-000007"
  tag stig_id: "PHTN-10-000007"
  tag cci: "CCI-000067"
  tag nist: ["AC-17 (1)", "Rev_4"]
  desc 'check', "At the command line, execute the following command:

# grep \"^authpriv\" /etc/rsyslog.conf

Expected result:

authpriv.*   /var/log/audit/sshinfo.log

If the command does not return any output, this is a finding.
"
  desc 'fix', "Open /etc/rsyslog.conf with a text editor and locate the
following line:

$IncludeConfig /etc/vmware-syslog/syslog.conf

Ensure that the following entry is put beneath the stated line and before the
\"# vmware services\" line.

authpriv.*   /var/log/audit/sshinfo.log

If the following line is at the end of the file it must be removed or commented
out:

auth.* /var/log/auth.log

At the command line, execute the following command:

# systemctl restart syslog
# service sshd reload"

  describe command('grep "authpriv" /etc/rsyslog.conf') do
    its ('stdout.strip') { should cmp 'authpriv.*   /var/log/audit/sshinfo.log' }
  end

end

