control 'UBTU-22-251015' do
  title 'Ubuntu 22.04 LTS must enable and run the Uncomplicated Firewall (ufw).'
  desc 'Remote access services, such as those providing remote access to network devices and information systems, which lack automated control capabilities, increase risk and make remote user access management difficult at best.

Remote access is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Ubuntu 22.04 LTS functionality (e.g., RDP) must be capable of taking enforcement action if the audit reveals unauthorized activity. Automated control of remote access sessions allows organizations to ensure ongoing compliance with remote access policies by enforcing connection rules of remote access applications on a variety of information system components (e.g., servers, workstations, notebook computers, smartphones, and tablets).'
  desc 'check', 'Verify the ufw is enabled on the system with the following command:

     $ sudo ufw status
     Status: active

If the above command returns the status as "inactive" or any type of error, this is a finding.'
  desc 'fix', 'Enable the ufw by using the following command:

     $ sudo ufw enable'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64244r953356_chk'
  tag severity: 'medium'
  tag gid: 'V-260515'
  tag rid: 'SV-260515r958672_rule'
  tag stig_id: 'UBTU-22-251015'
  tag gtitle: 'SRG-OS-000297-GPOS-00115'
  tag fix_id: 'F-64152r953357_fix'
  tag 'documentable'
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']

  if package('ufw').installed?
    describe command('sudo ufw status') do
      its('stdout') { should match /Status:\s+active/ }
    end
  else
    describe 'UFW Package is not installed' do
      skip 'UFW package not installed'
    end
  end
end
