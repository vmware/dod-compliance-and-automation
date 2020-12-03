control 'V-219231' do
  title "The Ubuntu operating system must be configured so that the audit log directory
    is not write-accessible by unauthorized users."
  desc  "Unauthorized disclosure of audit records can reveal system and
    configuration data to attackers, thus compromising its confidentiality.

    Audit information includes all information (e.g., audit records, audit
    settings, audit reports) needed to successfully audit Ubuntu operating system
    activity.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000059-GPOS-00029"
  tag "satisfies": nil
  tag "gid": 'V-219231'
  tag "rid": "SV-219231r378655_rule"
  tag "stig_id": "UBTU-18-010308"
  tag "fix_id": "F-20955r305022_fix"
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
  desc 'check', "Verify that the audit log directory has a mode of \"0750\" or less permissive.

    First determine where the audit logs are stored with the following command:

    # sudo grep -iw log_file /etc/audit/auditd.conf
    log_file = /var/log/audit/audit.log

    Using the path of the directory containing the audit logs, check if the directory
    has a mode of \"0750\" or less by using the following command:

    # sudo stat -c \"%n %a\" /var/log/audit
    /var/log/audit 750

    If the audit log directory has a mode more permissive than \"0750\", this is a finding.
  "
  desc 'fix', "Configure the audit log directory to have a mode of \"0750\" or less permissive.

    First determine where the audit logs are stored with the following command:

    # sudo grep -iw log_file /etc/audit/auditd.conf
    log_file = /var/log/audit/audit.log

    Using the path of the directory containing the audit logs, configure the audit
    log directory to have a mode of \"0750\" or less permissive by using the following command:

    # chmod -R g-w,o-rwx /var/log/audit
  "
  log_file_path = input('log_file_path')
  log_dir = input('log_file_dir')

  log_file_and_dir_exist = !log_file_path.nil? && !log_dir.nil?
  if log_file_and_dir_exist
    describe directory(log_dir) do
      it { should_not be_more_permissive_than('0750') }
    end
  else
    describe ('Audit log file:' + log_file_path + ' and/or audit directory:' + log_dir + ' exist') do
      subject { log_file_and_dir_exist }
      it { should be true }
    end
  end
end
