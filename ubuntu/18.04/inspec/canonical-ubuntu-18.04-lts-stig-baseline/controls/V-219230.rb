control 'V-219230' do
  title "The Ubuntu operating system must permit only authorized groups to own the
    audit log files."
  desc  "Unauthorized disclosure of audit records can reveal system and
    configuration data to attackers, thus compromising its confidentiality.

    Audit information includes all information (e.g., audit records, audit
    settings, audit reports) needed to successfully audit Ubuntu operating system
    activity.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000058-GPOS-00028"
  tag "satisfies": nil
  tag "gid": 'V-219230'
  tag "rid": "SV-219230r378652_rule"
  tag "stig_id": "UBTU-18-010307"
  tag "fix_id": "F-20954r305019_fix"
  tag "cci": [ "CCI-000162","CCI-000163" ]
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
  desc 'check', "Verify that the audit log files are owned by \"root\" group.

    First determine where the audit logs are stored with the following command:

    # sudo grep -iw log_file /etc/audit/auditd.conf
    log_file = /var/log/audit/audit.log

    Using the path of the directory containing the audit logs, check if the audit log files
    are owned by the \"root\" group by using the following command:

    # sudo stat -c \"%n %G\" /var/log/audit/*
    /var/log/audit/audit.log root

    If the audit log files are owned by a group other than \"root\", this is a finding.
  "
  desc 'fix', "Configure the audit log files to be owned by \"root\" group.

    First determine where the audit logs are stored with the following command:

    # sudo grep -iw log_file /etc/audit/auditd.conf
    log_file = /var/log/audit/audit.log

    Using the path of the directory containing the audit logs, configure the audit log files
    to be owned by \"root\" group by using the following command:

    # sudo chown :root /var/log/audit/*
  "
  log_file_path = auditd_conf.log_file

  describe file(log_file_path) do
    its('group') { should cmp 'root' }
  end
end
