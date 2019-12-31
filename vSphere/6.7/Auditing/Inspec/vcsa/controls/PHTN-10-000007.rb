control "PHTN-10-000007" do
  title "The Photon operating system must have sshd authentication logging
enabled."
  desc  "Automated monitoring of remote access sessions allows organizations to
detect cyber attacks and ensure ongoing compliance with remote access policies
by auditing connection activities.

    Shipping sshd authentication events to syslog allows organizations to use
their log aggregators to correlate forensic activities among multiple systems.
  "
  tag severity: nil
  tag gtitle: "SRG-OS-000032-GPOS-00013"
  tag gid: nil
  tag rid: "PHTN-10-000007"
  tag stig_id: "PHTN-10-000007"
  tag fix_id: nil
  tag cci: "CCI-000067"
  tag nist: ["AC-17 (1)", "Rev_4"]
  tag false_negatives: nil
  tag false_positives: nil
  tag documentable: nil
  tag mitigations: nil
  tag severity_override_guidance: nil
  tag potential_impacts: nil
  tag third_party_tools: nil
  tag mitigation_controls: nil
  tag responsibility: nil
  tag ia_controls: "AC-17 (1)"
  tag check: "At the command line, execute the following command:

# grep \"authpriv\" /etc/rsyslog.conf

Expected result:

auth.*;authpriv.* -/var/log/auth.log

If the command does not return any output, this is a finding.
"
  tag fix: "Open /etc/rsyslog.conf with a text editor and locate the
following line:

$IncludeConfig /etc/vmware-syslog/syslog.conf

Ensure that the following entry is put beneath the stated line and before the
\"# vmware services\" line.

auth.*;authpriv.* -/var/log/auth.log

If the following line is at the end of the file it must be removed or commented
out:

auth.*  /var/log/auth.log

At the command line, execute the following command:

# systemctl restart syslog
# service sshd reload"

  describe command('grep "authpriv" /etc/rsyslog.conf') do
    its ('stdout.strip') { should cmp 'authpriv.*   /var/log/audit/sshinfo.log' }
  end

end

