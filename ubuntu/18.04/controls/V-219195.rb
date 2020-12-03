control 'V-219195' do
  title 'The Ubuntu operating system must configure audit tools with a mode of
    0755 or less permissive.'
  desc  "Protecting audit information also includes identifying and protecting
    the tools used to view and manipulate log data. Therefore, protecting audit
    tools is necessary to prevent unauthorized operation on audit information.

    Ubuntu operating systems providing tools to interface with audit
    information will leverage user permissions and roles identifying the user
    accessing the tools and the corresponding rights the user enjoys in order to
    make access decisions regarding the access to audit tools.

    Audit tools include, but are not limited to, vendor-provided and open
    source audit tools needed to successfully view and manipulate audit information
    system activity and records. Audit tools include custom queries and report
    generators.
  "

  impact 0.5
  tag "gtitle": "SRG-OS-000256-GPOS-00097"
  tag "satisfies": nil
  tag "gid": 'V-219195'
  tag "rid": "SV-219195r379237_rule"
  tag "stig_id": "UBTU-18-010128"
  tag "fix_id": "F-20919r304914_fix"
  tag "cci": [ "CCI-001493","CCI-001494","CCI-001495" ]
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
  desc 'check', "Verify the audit tools are protected from unauthorized access, deletion, or
    modification by checking the permissive mode.

    For each audit tool,
    /sbin/auditctl, /sbin/aureport, /sbin/ausearch, /sbin/autrace, /sbin/auditd,
    /sbin/audispd, /sbin/augenrules

    Check the permissions by running the following command:

    # stat -c \"%n %a\" /sbin/auditctl

    755 /sbin/auditctl

    If any of the audit tools have a mode more permissive than 0755, this is a finding.
  "
  desc 'fix', "Configure the audit tools on the Ubuntu operating system to be protected from
    unauthorized access by setting the correct permissive mode using the following command:

    # sudo chmod 0755 [audit_tool]

    Replace \"[audit_tool]\" with the audit tool that does not have the correct permissive
    mode.
  "
  audit_tools = input('audit_tools')

  audit_tools.each do |tool|
    describe file(tool) do
      it { should_not be_more_permissive_than('0755') }
    end
  end
end
