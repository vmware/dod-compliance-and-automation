control 'UBTU-22-653060' do
  title 'Ubuntu 22.04 LTS must be configured so that the audit log directory is not write-accessible by unauthorized users.'
  desc 'If audit information were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve.

To ensure the veracity of audit information, the operating system must protect audit information from unauthorized deletion. This requirement can be achieved through multiple methods, which will depend upon system architecture and design.

Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit information system activity.'
  desc 'check', 'Verify that the audit log directory has a mode of "750" or less permissive.

Determine where the audit logs are stored by using the following command:

     $ sudo grep -iw log_file /etc/audit/auditd.conf
     log_file = /var/log/audit/audit.log

Using the path of the directory containing the audit logs, determine if the directory has a mode of "750" or less by using the following command:

     $ sudo stat -c "%n %a" /var/log/audit
     /var/log/audit 750

If the audit log directory has a mode more permissive than "750", this is a finding.'
  desc 'fix', 'Configure the audit log directory to have a mode of "750" or less permissive.

Using the path of the directory containing the audit logs, configure the audit log directory to have a mode of "750" or less permissive by using the following command:

     $ sudo chmod -R  g-w,o-rwx /var/log/audit'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64329r953611_chk'
  tag severity: 'medium'
  tag gid: 'V-260600'
  tag rid: 'SV-260600r958438_rule'
  tag stig_id: 'UBTU-22-653060'
  tag gtitle: 'SRG-OS-000059-GPOS-00029'
  tag fix_id: 'F-64237r953612_fix'
  tag 'documentable'
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']

  log_file = auditd_conf.log_file

  log_dir_exists = !log_file.nil? && !File.dirname(log_file).nil?
  if log_dir_exists
    describe directory(File.dirname(log_file)) do
      it { should_not be_more_permissive_than('0750') }
    end
  else
    describe("Audit directory for file #{log_file} exists") do
      subject { log_dir_exists }
      it { should be true }
    end
  end
end
