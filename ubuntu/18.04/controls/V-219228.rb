control 'V-219228' do
  title "The Ubuntu operating system must be configured so that audit log files cannot be
    read or write-accessible by unauthorized users."
  desc  "Unauthorized disclosure of audit records can reveal system and
    configuration data to attackers, thus compromising its confidentiality.

    Audit information includes all information (e.g., audit records, audit
    settings, audit reports) needed to successfully audit Ubuntu operating system
    activity.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000058-GPOS-00028"
  tag "satisfies": nil
  tag "gid": 'V-219228'
  tag "rid": "SV-219228r378652_rule"
  tag "stig_id": "UBTU-18-010305"
  tag "fix_id": "F-20952r305013_fix"
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
  desc 'check', "Verify that the audit log files have a mode of \"0600\" or less permissive.

    First determine where the audit logs are stored with the following command:

    # sudo grep -iw log_file /etc/audit/auditd.conf
    log_file = /var/log/audit/audit.log

    Using the path of the directory containing the audit logs, check if the audit log files
    have a mode of \"0600\" or less by using the following command:

    # sudo stat -c \"%n %a\" /var/log/audit/*
    /var/log/audit/audit.log 600

    If the audit log files have a mode more permissive than \"0600\", this is a finding.
  "
  desc 'fix', "Configure the audit log files to have a mode of \"0600\" or less permissive.

    First determine where the audit logs are stored with the following command:

    # sudo grep -iw log_file /etc/audit/auditd.conf
    log_file = /var/log/audit/audit.log

    Using the path of the directory containing the audit logs, configure the audit log files
    to have a mode of \"0600\" or less permissive by using the following command:

    # sudo chmod 0600 /var/log/audit/*
  "
  log_file = auditd_conf.log_file

  log_file_exists = !log_file.nil?
  if log_file_exists
    describe file(log_file) do
      it { should_not be_more_permissive_than('0600') }
    end
  else
    describe ('Audit log file ' + log_file + ' exists') do
      subject { log_file_exists }
      it { should be true }
    end
  end
end
