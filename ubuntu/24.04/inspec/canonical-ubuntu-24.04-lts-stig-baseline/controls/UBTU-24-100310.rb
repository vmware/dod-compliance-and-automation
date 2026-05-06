control 'UBTU-24-100310' do
  title 'Ubuntu 24.04 LTS must enable and run the Uncomplicated Firewall (ufw).'
  desc 'Remote access services, such as those providing remote access to network devices and information systems, which lack automated control capabilities, increase risk, and make remote user access management difficult at best.

Remote access is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Ubuntu 24.04 LTS functionality (e.g., RDP) must be capable of taking enforcement action if the audit reveals unauthorized activity. Automated control of remote access sessions allows organizations to ensure ongoing compliance with remote access policies by enforcing connection rules of remote access applications on a variety of information system components (e.g., servers, workstations, notebook computers, smartphones, and tablets).

'
  desc 'check', 'Verify the ufw is enabled on the system with the following command:

$ sudo ufw status
Status: active

If the above command returns the status as "inactive" or any type of error, this is a finding.

If the ufw is not installed, ask the system administrator if another application firewall is installed. If a different firewall is active on the system, this is not a finding.'
  desc 'fix', 'Enable the ufw by using the following command:

$ sudo ufw enable

Note: Enabling the firewall will potentially disrupt ssh sessions.'
  impact 0.5
  tag check_id: 'C-74688r1066452_chk'
  tag severity: 'medium'
  tag gid: 'V-270655'
  tag rid: 'SV-270655r1067145_rule'
  tag stig_id: 'UBTU-24-100310'
  tag gtitle: 'SRG-OS-000297-GPOS-00115'
  tag fix_id: 'F-74589r1067144_fix'
  tag satisfies: ['SRG-OS-000297-GPOS-00115', 'SRG-OS-000480-GPOS-00232']
  tag 'documentable'
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']

  if package('ufw').installed?
    describe command('ufw status') do
      its('stdout') { should match(/Status:\s+active/) }
    end
  else
    describe 'UFW Package is not installed' do
      skip 'UFW package not installed'
    end
  end
end
