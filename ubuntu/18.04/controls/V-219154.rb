control 'V-219154' do
  title "The Ubuntu operating system must have a crontab script running weekly to off-load
    audit events of standalone systems."
  desc  "Information stored in one location is vulnerable to accidental or incidental
    deletion or alteration.

    Off-loading is a common process in information systems with limited audit storage capacity.
  "
  impact 0.3
  tag "gtitle": "SRG-OS-000479-GPOS-00224"
  tag "gid": 'V-219154'
  tag "rid": "SV-219154r381499_rule"
  tag "stig_id": "UBTU-18-010008"
  tag "fix_id": "F-20878r304791_fix"
  tag "cci": [ "CCI-001851" ]
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
  desc 'check', "Verify there is a script which off-loads audit data and if that script runs
    weekly.

    Check if there is a script in the /etc/cron.weekly directory which off-loads audit data:

    # sudo ls /etc/cron.weekly

    audit-offload

    Check if the script inside the file does offloading of audit logs to an external media.

    If the script file does not exist or if the script file doesn't offload audit logs, this
    is a finding.
  "
  desc 'fix', "Create a script which off-loads audit logs to external media and runs weekly.

    Script must be located into the /etc/cron.weekly directory.
  "
  describe 'Not Applicable' do
    skip 'Logging (auditsp-remote)'
  end
end
