control "V-219219" do
  title "The Ubuntu operating system must generate audit records for the /var/log/btmp file."
  desc "Without generating audit records that are specific to the security and mission needs
    of the organization, it would be difficult to establish, correlate, and investigate the
    events relating to an incident or identify those responsible for one.

    Audit records can be generated from various components within the information system
    (e.g., module or policy filter).
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000472-GPOS-00217"
  tag "satisfies": nil
  tag "gid": "V-219219"
  tag "rid": "SV-219219r381478_rule"
  tag "stig_id": "UBTU-18-010240"
  tag "fix_id": "F-20943r304986_fix"
  tag "cci": [ "CCI-000172" ]
  tag "nist": nil
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  desc "check", "Verify the Ubuntu operating system generates audit records showing start
    and stop times for user access to the system via \"/var/log/btmp\".

    Check the auditing rules in \"/etc/audit/audit.rules\" with the following
    command:

    # sudo grep /var/log/btmp /etc/audit/audit.rules

    -w /var/log/btmp -p wa -k logins

    If the command does not return a line, or the line is commented out, this is a
    finding.
  "
  desc "fix", "Configure the Ubuntu operating system generates audit records showing start
    and stop times for user access to the system via \"/var/log/btmp\".

    Add or update the following file system rule to \"/etc/audit/audit.rules\":

    -w /var/log/btmp -p wa -k identity

    The audit daemon must be restarted for the changes to take effect. To restart
    the audit daemon, run the following command:

    # sudo systemctl restart auditd.service
  "

  @audit_file = "/var/log/btmp"

  audit_lines_exist = !auditd.lines.index { |line| line.include?(@audit_file) }.nil?
  if audit_lines_exist
    describe auditd.file(@audit_file) do
      its("permissions") { should_not cmp [] }
      its("action") { should_not include "never" }
    end

    @perms = auditd.file(@audit_file).permissions

    @perms.each do |perm|
      describe perm do
        it { should include "w" }
        it { should include "a" }
      end
    end
  else
    describe ("Audit line(s) for " + @audit_file + " exist") do
      subject { audit_lines_exist }
      it { should be true }
    end
  end
end
