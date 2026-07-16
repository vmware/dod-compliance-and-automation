control 'UBTU-24-100130' do
  title 'Ubuntu 24.04 LTS must notify designated personnel if baseline configurations are changed in an unauthorized manner. The file integrity tool must notify the system administrator (SA) when changes to the baseline configuration or anomalies in the operation of any security functions are discovered.'
  desc "Unauthorized changes to the baseline configuration could make the system vulnerable to various attacks or allow unauthorized access to Ubuntu 24.04 LTS. Changes to Ubuntu 24.04 LTS configurations can have unintended side effects, some of which may be relevant to security.

Detecting such changes and providing an automated response can help avoid unintended, negative consequences that could ultimately affect the security state of Ubuntu 24.04 LTS. Ubuntu 24.04 LTS' IMO/information system security officer (ISSO) and SAs must be notified via email and/or monitoring system trap when there is an unauthorized modification of a configuration item.

"
  desc 'check', 'Verify that Advanced Intrusion Detection Environment (AIDE) notifies the SA when anomalies in the operation of any security functions are discovered with the following command:

$ grep SILENTREPORTS /etc/default/aide
SILENTREPORTS=no

If "SILENTREPORTS" is set to "yes", is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to notify designated personnel if baseline configurations are changed in an unauthorized manner.

Modify the "SILENTREPORTS" parameter in the "/etc/default/aide" file with a value of "no" if it does not already exist as follows:

SILENTREPORTS=no'
  impact 0.5
  tag check_id: 'C-74685r1066443_chk'
  tag severity: 'medium'
  tag gid: 'V-270652'
  tag rid: 'SV-270652r1067138_rule'
  tag stig_id: 'UBTU-24-100130'
  tag gtitle: 'SRG-OS-000447-GPOS-00201'
  tag fix_id: 'F-74586r1067137_fix'
  tag satisfies: ['SRG-OS-000447-GPOS-00201', 'SRG-OS-000363-GPOS-00150']
  tag 'documentable'
  tag cci: ['CCI-002702', 'CCI-001744']
  tag nist: ['SI-6 d', 'CM-3 (5)']

  describe file('/etc/default/aide') do
    it { should exist }
    its('content') { should match '^SILENTREPORTS=no$' }
  end
end
