control 'V-219197' do
  title 'The Ubuntu operating system must configure the audit tools to be
    group-owned by root.'
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
  tag "gid": 'V-219197'
  tag "rid": "SV-219197r379237_rule"
  tag "stig_id": "UBTU-18-010130"
  tag "fix_id": "F-20921r304920_fix"
  tag "cci": [ "CCI-001493" ]
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
  desc 'check', "Verify the Ubuntu operating system configures the audit tools to be
    group-owned by root to prevent any unauthorized access, deletion, or modification.

    For each audit tools,
    /sbin/auditctl, /sbin/aureport, /sbin/ausearch, /sbin/autrace, /sbin/auditd,
    /sbin/audispd, /sbin/augenrules

    Check the group-owner of each audit tool by running the following commands:

    stat -c \"%n %G\" /sbin/auditctl

    /sbin/auditctl root

    If any of the audit tools are not group-owned by root, this is a finding.
  "

  desc 'fix', "Configure the audit tools on the Ubuntu operating system to be group-owned
    by root, by running the following command:

    # sudo chgrp root [audit_tool]

    Replace \"[audit_tool]\" with each audit tool not group-owned by root.
  "

  audit_tools = input('audit_tools')

  audit_tools.each do |tool|
    describe file(tool) do
      its('group') { should cmp 'root' }
    end
  end
end
