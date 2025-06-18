control 'UBTU-22-652010' do
  title 'Ubuntu 22.04 LTS must be configured to preserve log records from failure events.'
  desc 'Failure to a known state can address safety or security in accordance with the mission/business needs of the organization. Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system.

Preserving operating system state information helps to facilitate operating system restart and return to the operational mode of the organization with least disruption to mission/business processes.'
  desc 'check', 'Verify the log service is installed properly by using the following command:

     $ dpkg -l | grep rsyslog
     ii     rsyslog     8.2112.0-2ubuntu2.2     amd64     reliable system and kernel logging daemon

If the "rsyslog" package is not installed, this is a finding.

Check that the log service is enabled and active by using the following commands:

     $ systemctl is-enabled rsyslog.service
     enabled

     $ systemctl is-active rsyslog.service
     active

If "rsyslog.service" is not enabled and active, this is a finding.'
  desc 'fix', 'Install the log service by using the following command:

     $ sudo apt-get install rsyslog

Enable and activate the log service by using the following command:

     $ sudo systemctl enable rsyslog.service --now'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64317r953575_chk'
  tag severity: 'medium'
  tag gid: 'V-260588'
  tag rid: 'SV-260588r991562_rule'
  tag stig_id: 'UBTU-22-652010'
  tag gtitle: 'SRG-OS-000269-GPOS-00103'
  tag fix_id: 'F-64225r953576_fix'
  tag 'documentable'
  tag cci: ['CCI-001665']
  tag nist: ['SC-24']

  describe service('rsyslog') do
    it { should be_installed }
    it { should be_enabled }
    it { should be_running }
  end
end
