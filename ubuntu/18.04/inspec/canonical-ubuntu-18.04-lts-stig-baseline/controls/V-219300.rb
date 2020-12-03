control "V-219300" do
  title "TThe Ubuntu operating system must generate audit records when
    successful/unsuccessful attempts to use the fdisk command."
  desc "Without generating audit records that are specific to the security and
    mission needs of the organization, it would be difficult to establish, correlate, and i
    nvestigate the events relating to an incident or identify those responsible for one.

    Audit records can be generated from various components within the information
    system (e.g., module or policy filter).
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000477-GPOS-00222"
  tag "satisfies": nil
  tag "gid": "V-219300"
  tag "rid": "SV-219300r381493_rule"
  tag "stig_id": "UBTU-18-010392"
  tag "fix_id": "F-21024r305229_fix"
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
  desc "check", "Verify if the Ubuntu operating system is configured to
    audit the execution of the partition management program \"fdisk\".

    Check the currently configured audit rules with the following command:

    # sudo auditctl -l | grep fdisk

    -w /sbin/fdisk -p x -k fdisk

    If the command does not return a line, or the line is commented out, this is a finding.
  "

  desc "fix", "Configure the Ubuntu operating system to audit the execution of the
    partition management program \"fdisk\".

    Add or update the following rule in the \"/etc/audit/rules.d/stig.rules\" file.

    -w /bin/fdisk -p x -k fdisk

    In order to reload the rules file, issue the following command:

    # sudo augenrules --load
  "

  @audit_file = "/sbin/fdisk"

  audit_lines_exist = !auditd.lines.index { |line| line.include?(@audit_file) }.nil?
  if audit_lines_exist
    describe auditd.file(@audit_file) do
      its("permissions") { should_not cmp [] }
      its("action") { should_not include "never" }
    end

    @perms = auditd.file(@audit_file).permissions

    @perms.each do |perm|
      describe perm do
        it { should include "x" }
      end
    end
  else
    describe ("Audit line(s) for " + @audit_file + " exist") do
      subject { audit_lines_exist }
      it { should be true }
    end
  end
end
