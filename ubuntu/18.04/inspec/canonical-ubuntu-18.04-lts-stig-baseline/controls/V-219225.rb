# encoding: UTF-8

control 'V-219225' do
  title "The Ubuntu operating system must produce audit records and reports
containing information to establish when, where, what type, the source, and the
outcome for all DoD-defined auditable events and actions in near real time."
  desc  "Without establishing the when, where, type, source, and outcome of
events that occurred, it would be difficult to establish, correlate, and
investigate the events leading up to an outage or attack.

    Without the capability to generate audit records, it would be difficult to
establish, correlate, and investigate the events relating to an incident or
identify those responsible for one.

    Audit record content that may be necessary to satisfy this requirement
includes, for example, time stamps, source and destination addresses,
user/process identifiers, event descriptions, success/fail indications,
filenames involved, and access control or flow control rules invoked.

    Reconstruction of harmful events or forensic analysis is not possible if
audit records do not contain enough information.

    Successful incident response and auditing relies on timely, accurate system
information and analysis in order to allow the organization to identify and
respond to potential incidents in a proficient manner. If the operating system
does not provide the ability to centrally review the operating system logs,
forensic analysis is negatively impacted.

    Associating event types with detected events in the Ubuntu operating system
audit logs provides a means of investigating an attack; recognizing resource
utilization or capacity thresholds; or identifying an improperly configured
operating system.


  "
  desc  'rationale', ''
  desc  'check', "
    Verify the audit service is configured to produce audit records.

    Check that the audit service is installed properly with the following
command:

    # dpkg -l | grep auditd

    If the \"auditd\" package is not installed, this is a finding.

    Check that the audit service is enabled with the following command:

    # systemctl is-enabled auditd.service

    If the command above returns \"disabled\", this is a finding.

    Check that the audit service is properly running and active on the system
with the following command:

    # systemctl is-active auditd.service
    active

    If the command above returns \"inactive\", this is a finding.
  "
  desc  'fix', "
    Configure the audit service to produce audit records containing the
information needed to establish when (date and time) an event occurred.

    Install the audit service (if the audit service is not already installed)
with the following command:

    # sudo apt-get install auditd

    Enable the audit service with the following command:

    # sudo systemctl enable auditd.service

    In order to reload the rules file, issue the following command:

    # sudo augenrules --load
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000038-GPOS-00016'
  tag satisfies: ['SRG-OS-000038-GPOS-00016', 'SRG-OS-000039-GPOS-00017',
'SRG-OS-000040-GPOS-00018', 'SRG-OS-000041-GPOS-00019',
'SRG-OS-000042-GPOS-00020', 'SRG-OS-000042-GPOS-00021',
'SRG-OS-000051-GPOS-00024', 'SRG-OS-000054-GPOS-00025',
'SRG-OS-000062-GPOS-00031', 'SRG-OS-000122-GPOS-00063',
'SRG-OS-000337-GPOS-00129', 'SRG-OS-000348-GPOS-00136',
'SRG-OS-000349-GPOS-00137', 'SRG-OS-000350-GPOS-00138',
'SRG-OS-000351-GPOS-00139', 'SRG-OS-000352-GPOS-00140',
'SRG-OS-000365-GPOS-00152', 'SRG-OS-000392-GPOS-00172',
'SRG-OS-000475-GPOS-00220']
  tag gid: 'V-219225'
  tag rid: 'SV-219225r508662_rule'
  tag stig_id: 'UBTU-18-010250'
  tag fix_id: 'F-20949r305004_fix'
  tag cci: ['SV-109781', 'V-100677', 'CCI-001814', 'CCI-001914', 'CCI-001875',
'CCI-001876', 'CCI-001877', 'CCI-001878', 'CCI-001879', 'CCI-001880',
'CCI-000172', 'CCI-000169', 'CCI-000131', 'CCI-000132', 'CCI-000133',
'CCI-000134', 'CCI-000135', 'CCI-000154', 'CCI-000158', 'CCI-002884']
  tag nist: ['CM-5 (1)', 'AU-12 (3)', 'AU-7 a', 'AU-7 a', 'AU-7 a', 'AU-7 a',
'AU-7 a', 'AU-7 a', 'AU-12 c', 'AU-12 a', 'AU-3', 'AU-3', 'AU-3', 'AU-3', "AU-3
(1)", 'AU-6 (4)', 'AU-7 (1)', 'MA-4 (1) (a)']

  describe package('auditd') do
    it { should be_installed }
  end
  describe service('auditd') do
    it { should be_installed }
    it { should be_enabled }
    it { should be_running }
  end
end

