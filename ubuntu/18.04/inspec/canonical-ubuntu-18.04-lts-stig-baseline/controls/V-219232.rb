control 'V-219232' do
  title "The Ubuntu operating system must allow only authorized accounts to own the audit
    log directory."
  desc  "Unauthorized disclosure of audit records can reveal system and
    configuration data to attackers, thus compromising its confidentiality.

    Audit information includes all information (e.g., audit records, audit
    settings, audit reports) needed to successfully audit Ubuntu operating system
    activity.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000059-GPOS-00029"
  tag "satisfies": nil
  tag "gid": 'V-219232'
  tag "rid": "SV-219232r378655_rule"
  tag "stig_id": "UBTU-18-010309"
  tag "fix_id": "F-20956r305025_fix"
  tag "cci": [ "CCI-000164" ]
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
  desc 'check', "Verify that the audit log directory is owned by \"root\" account.

    First determine where the audit logs are stored with the following command:

    # sudo grep -iw log_file /etc/audit/auditd.conf
    log_file = /var/log/audit/audit.log

    Using the path of the directory containing the audit logs, check if the directory is
    owned by the \"root\" user by using the following command:

    # sudo stat -c \"%n %U\" /var/log/audit
    /var/log/audit root

    If the audit log directory is owned by an user other than \"root\", this is a finding.
  "
  desc 'fix', "Configure the audit log directory to be owned by \"root\" user.

    First determine where the audit logs are stored with the following command:

    # sudo grep -iw log_file /etc/audit/auditd.conf
    log_file = /var/log/audit/audit.log

    Using the path of the directory containing the audit logs, configure the audit log
    directory to be owned by \"root\" user by using the following command:

    # chown -R root /var/log/audit
  "
  log_file_dir = input('log_file_dir')

  describe directory(log_file_dir) do
    its('owner') { should cmp 'root' }
  end
end
