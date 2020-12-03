control 'V-219225' do
  title "The Ubuntu operating system must produce audit records and reports containing
    information to establish when, where, what type, the source, and the outcome for all
    DoD-defined auditable events and actions in near real time."
  desc  "Without establishing what type of events occurred, the source of
    events, where events occurred, and the outcome of events, it would be difficult
    to establish, correlate, and investigate the events leading up to an outage or
    attack.

    Audit record content that may be necessary to satisfy this requirement
    includes, for example, time stamps, source and destination addresses,
    user/process identifiers, event descriptions, success/fail indications,
    filenames involved, and access control or flow control rules invoked.

    Associating event types with detected events in the Ubuntu operating system
    audit logs provides a means of investigating an attack, recognizing resource
    utilization or capacity thresholds, or identifying an improperly configured
    Ubuntu operating system.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000038-GPOS-00016"
  tag "satisfies": nil
  tag "gid": 'V-219225'
  tag "rid": "SV-219225r378619_rule"
  tag "stig_id": "UBTU-18-010250"
  tag "fix_id": "F-20949r305004_fix"
  tag "cci": [ "CCI-000131","CCI-000132","CCI-000133","CCI-000134","CCI-000135","CCI-000154","CCI-000158","CCI-000169","CCI-000172","CCI-001814","CCI-001875","CCI-001876","CCI-001877","CCI-001878","CCI-001879","CCI-001880","CCI-001914","CCI-002884" ]
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
  desc 'check', "Verify the audit service is configured to produce audit records.

    Check that the audit service is installed properly with the following command:

    # dpkg -l | grep auditd

    If the \"auditd\" package is not installed, this is a finding.

    Check that the audit service is enabled with the following command:

    # systemctl is-enabled auditd.service

    If the command above returns \"disabled\", this is a finding.

    Check that the audit service is properly running and active on the system with the
    following command:

    # systemctl is-active auditd.service
    active

    If the command above returns \"inactive\", this is a finding.
  "

  desc 'fix', "Configure the audit service to produce audit records containing the
    information needed to establish when (date and time) an event occurred.

    Install the audit service (if the audit service is not already installed) with the
    following command:

    # sudo apt-get install auditd

    Enable the audit service with the following command:

    # sudo systemctl enable auditd.service

    In order to reload the rules file, issue the following command:

    # sudo augenrules --load
  "

  describe package('auditd') do
    it { should be_installed }
  end
  describe service('auditd') do
    it { should be_installed }
    it { should be_enabled }
    it { should be_running }
  end
end
