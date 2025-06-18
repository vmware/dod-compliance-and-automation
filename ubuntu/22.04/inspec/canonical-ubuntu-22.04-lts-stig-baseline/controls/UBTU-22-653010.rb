control 'UBTU-22-653010' do
  title 'Ubuntu 22.04 LTS must have the "auditd" package installed.'
  desc 'Without establishing the when, where, type, source, and outcome of events that occurred, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit record content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.

Successful incident response and auditing relies on timely, accurate system information and analysis in order to allow the organization to identify and respond to potential incidents in a proficient manner. If the operating system does not provide the ability to centrally review the operating system logs, forensic analysis is negatively impacted.

Associating event types with detected events in Ubuntu 22.04 LTS audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured operating system.

'
  desc 'check', 'Verify the "auditd" package is installed by using the following command:

     $ dpkg -l | grep auditd
     ii     libauditd     1:3.0.7-1build1     amd64     User space tools for security auditing

If the "auditd" package is not installed, this is a finding.'
  desc 'fix', 'Install the "auditd" package by using the following command:

     $ sudo apt-get install auditd'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64319r953581_chk'
  tag severity: 'medium'
  tag gid: 'V-260590'
  tag rid: 'SV-260590r1015022_rule'
  tag stig_id: 'UBTU-22-653010'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-64227r953582_fix'
  tag satisfies: ['SRG-OS-000037-GPOS-00015', 'SRG-OS-000038-GPOS-00016', 'SRG-OS-000039-GPOS-00017', 'SRG-OS-000040-GPOS-00018', 'SRG-OS-000041-GPOS-00019', 'SRG-OS-000042-GPOS-00020', 'SRG-OS-000042-GPOS-00021', 'SRG-OS-000051-GPOS-00024', 'SRG-OS-000054-GPOS-00025', 'SRG-OS-000062-GPOS-00031', 'SRG-OS-000122-GPOS-00063', 'SRG-OS-000337-GPOS-00129', 'SRG-OS-000348-GPOS-00136', 'SRG-OS-000349-GPOS-00137', 'SRG-OS-000350-GPOS-00138', 'SRG-OS-000351-GPOS-00139', 'SRG-OS-000352-GPOS-00140', 'SRG-OS-000353-GPOS-00141', 'SRG-OS-000354-GPOS-00142', 'SRG-OS-000365-GPOS-00152', 'SRG-OS-000475-GPOS-00220']
  tag 'documentable'
  tag cci: ['CCI-000130', 'CCI-000131', 'CCI-000132', 'CCI-000133', 'CCI-000134', 'CCI-000135', 'CCI-000154', 'CCI-000158', 'CCI-000169', 'CCI-000172', 'CCI-001814', 'CCI-001875', 'CCI-001876', 'CCI-001877', 'CCI-001878', 'CCI-001879', 'CCI-001880', 'CCI-001881', 'CCI-001882', 'CCI-001914', 'CCI-003938']
  tag nist: ['AU-3 a', 'AU-3 b', 'AU-3 c', 'AU-3 d', 'AU-3 e', 'AU-3 (1)', 'AU-6 (4)', 'AU-7 (1)', 'AU-12 a', 'AU-12 c', 'CM-5 (1)', 'AU-7 a', 'AU-7 b', 'AU-12 (3)', 'CM-5 (1) (b)']

  describe package('auditd') do
    it { should be_installed }
  end
end
