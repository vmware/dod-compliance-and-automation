control 'UBTU-22-251020' do
  title 'Ubuntu 22.04 LTS must have an application firewall enabled.'
  desc 'Firewalls protect computers from network attacks by blocking or limiting access to open network ports. Application firewalls limit which applications are allowed to communicate over the network.'
  desc 'check', 'Verify the Uncomplicated Firewall (ufw) is enabled on the system with the following command:

     $ systemctl status ufw.service | grep -i "active:"
     Active: active (exited) since Thu 2022-12-25 00:00:01 NZTD; 365 days 11h ago

If "ufw.service" is "inactive", this is a finding.

If the ufw is not installed, ask the system administrator if another application firewall is installed. If no application firewall is installed, this is a finding.'
  desc 'fix', 'Enable and start the ufw by using the following command:

     $ sudo systemctl enable ufw.service --now'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64245r953359_chk'
  tag severity: 'medium'
  tag gid: 'V-260516'
  tag rid: 'SV-260516r991593_rule'
  tag stig_id: 'UBTU-22-251020'
  tag gtitle: 'SRG-OS-000480-GPOS-00232'
  tag fix_id: 'F-64153r953360_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if package('ufw').installed?
    describe command('systemctl status ufw.service') do
      its('stdout') { should match /Active: active/ }
    end
  else
    describe 'UFW Package is not installed' do
      skip 'UFW package not installed'
    end
  end
end
