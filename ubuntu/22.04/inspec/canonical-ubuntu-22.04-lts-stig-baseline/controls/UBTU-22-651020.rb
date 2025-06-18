control 'UBTU-22-651020' do
  title 'Ubuntu 22.04 LTS must notify designated personnel if baseline configurations are changed in an unauthorized manner. The file integrity tool must notify the system administrator when changes to the baseline configuration or anomalies in the operation of any security functions are discovered.'
  desc "Unauthorized changes to the baseline configuration could make the system vulnerable to various attacks or allow unauthorized access to the operating system. Changes to operating system configurations can have unintended side effects, some of which may be relevant to security.

Detecting such changes and providing an automated response can help avoid unintended, negative consequences that could ultimately affect the security state of the operating system. The operating system's IMO/ISSO and SAs must be notified via email and/or monitoring system trap when there is an unauthorized modification of a configuration item.

"
  desc 'check', %q(Verify that Advanced Intrusion Detection Environment (AIDE) notifies the system administrator when anomalies in the operation of any security functions are discovered by using the following command:

     $ grep -i '^\s*silentreports' /etc/default/aide
     SILENTREPORTS=no

If "SILENTREPORTS" is set to "yes", is commented out, or is missing, this is a finding.)
  desc 'fix', 'Configure AIDE to notify designated personnel if baseline configurations are changed in an unauthorized manner.

Add or modify the following line in the "/etc/default/aide" file:

SILENTREPORTS=no'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64313r953563_chk'
  tag severity: 'medium'
  tag gid: 'V-260584'
  tag rid: 'SV-260584r958794_rule'
  tag stig_id: 'UBTU-22-651020'
  tag gtitle: 'SRG-OS-000363-GPOS-00150'
  tag fix_id: 'F-64221r953564_fix'
  tag satisfies: ['SRG-OS-000363-GPOS-00150', 'SRG-OS-000447-GPOS-00201']
  tag 'documentable'
  tag cci: ['CCI-001744', 'CCI-002702']
  tag nist: ['CM-3 (5)', 'SI-6 d']

  describe file('/etc/default/aide') do
    it { should exist }
    its('content') { should match '^SILENTREPORTS=no$' }
  end
end
