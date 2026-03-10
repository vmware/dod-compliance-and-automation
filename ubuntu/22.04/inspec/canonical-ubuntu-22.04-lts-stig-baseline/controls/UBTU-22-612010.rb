control 'UBTU-22-612010' do
  title 'Ubuntu 22.04 LTS must implement multifactor authentication for remote access to privileged accounts in such a way that one of the factors is provided by a device separate from the system gaining access.'
  desc 'Using an authentication device, such as a CAC or token separate from the information system, ensures that even if the information system is compromised, that compromise will not affect credentials stored on the authentication device.

Multifactor solutions that require devices separate from information systems gaining access include, for example, hardware tokens providing time-based or challenge-response authenticators and smart cards such as the U.S. Government personal identity verification card and the DOD common access card.

A privileged account is defined as an information system account with authorizations of a privileged user.

Remote access is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

This requirement only applies to components where this is specific to the function of the device or has the concept of an organizational user (e.g., VPN, proxy capability). This does not apply to authentication for the purpose of configuring the device itself (management).

'
  desc 'check', 'Verify Ubuntu 22.04 LTS has the packages required for multifactor authentication installed by using the following command:

     $ dpkg -l | grep libpam-pkcs11
     ii     libpam-pkcs11     0.6.11-4build2     amd64     Fully featured PAM module for using PKCS#11 smart cards

If the "libpam-pkcs11" package is not installed, this is a finding.'
  desc 'fix', 'Install the "libpam-pkcs11" package by using the following command:

     $ sudo apt-get install libpam-pkcs11'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64302r953530_chk'
  tag severity: 'medium'
  tag gid: 'V-260573'
  tag rid: 'SV-260573r1015019_rule'
  tag stig_id: 'UBTU-22-612010'
  tag gtitle: 'SRG-OS-000375-GPOS-00160'
  tag fix_id: 'F-64210r953531_fix'
  tag satisfies: ['SRG-OS-000375-GPOS-00160', 'SRG-OS-000105-GPOS-00052', 'SRG-OS-000106-GPOS-00053', 'SRG-OS-000107-GPOS-00054', 'SRG-OS-000108-GPOS-00055']
  tag 'documentable'
  tag cci: ['CCI-000765', 'CCI-000766', 'CCI-000767', 'CCI-000768', 'CCI-001948', 'CCI-004046', 'CCI-004047']
  tag nist: ['IA-2 (1)', 'IA-2 (2)', 'IA-2 (3)', 'IA-2 (4)', 'IA-2 (11)', 'IA-2 (6) (a)', 'IA-2 (6) (b)']

  describe package('libpam-pkcs11') do
    it { should be_installed }
  end
end
