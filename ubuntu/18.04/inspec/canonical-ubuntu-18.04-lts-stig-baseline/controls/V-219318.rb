# encoding: UTF-8

control 'V-219318' do
  title "The Ubuntu operating system must implement multifactor authentication
for remote access to privileged accounts in such a way that one of the factors
is provided by a device separate from the system gaining access."
  desc  "Using an authentication device, such as a CAC or token that is
separate from the information system, ensures that even if the information
system is compromised, that compromise will not affect credentials stored on
the authentication device.

    Multifactor solutions that require devices separate from information
systems gaining access include, for example, hardware tokens providing
time-based or challenge-response authenticators and smart cards such as the
U.S. Government Personal Identity Verification card and the DoD Common Access
Card.

    A privileged account is defined as an information system account with
authorizations of a privileged user.

    Remote access is access to DoD nonpublic information systems by an
authorized user (or an information system) communicating through an external,
non-organization-controlled network. Remote access methods include, for
example, dial-up, broadband, and wireless.

    This requirement only applies to components where this is specific to the
function of the device or has the concept of an organizational user (e.g., VPN,
proxy capability). This does not apply to authentication for the purpose of
configuring the device itself (management).

    Requires further clarification from NIST.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the Ubuntu operating system has the packages required for
multifactor authentication installed.

    Check for the presence of the packages required to support multifactor
authentication with the following commands:

    # dpkg -l | grep libpam-pkcs11

    ii libpam-pkcs11 0.6.8-4 amd64 Fully featured PAM module for using PKCS#11
smart cards

    If the \"libpam-pkcs11\" package is not installed, this is a finding.
  "
  desc  'fix', "
    Configure the Ubuntu operating system to implement multifactor
authentication by installing the required packages.

    Install the \"libpam-pkcs11\" package on the system with the following
command:

    # sudo apt install libpam-pkcs11
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000375-GPOS-00160'
  tag gid: 'V-219318'
  tag rid: 'SV-219318r508662_rule'
  tag stig_id: 'UBTU-18-010431'
  tag fix_id: 'F-21042r305283_fix'
  tag cci: ['V-100859', 'SV-109963', 'CCI-001948']
  tag nist: ['IA-2 (11)']

  describe package('libpam-pkcs11') do
    it { should be_installed }
  end
end

