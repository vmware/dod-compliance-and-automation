# encoding: UTF-8

control 'V-219307' do
  title "The Ubuntu operating system must implement DoD-approved encryption to
protect the confidentiality of remote access sessions."
  desc  "Without confidentiality protection mechanisms, unauthorized
individuals may gain access to sensitive information via a remote access
session.

    Remote access is access to DoD nonpublic information systems by an
authorized user (or an information system) communicating through an external,
non-organization-controlled network. Remote access methods include, for
example, dial-up, broadband, and wireless.

    Encryption provides a means to secure the remote connection to prevent
unauthorized access to the data traversing the remote access connection (e.g.,
RDP), thereby providing a degree of confidentiality. The encryption strength of
a mechanism is selected based on the security categorization of the information.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the SSH daemon is configured to only implement DoD-approved
encryption.

    Check the SSH daemon's current configured ciphers by running the following
command:

    # grep -E '^Ciphers ' /etc/ssh/sshd_config

    Ciphers aes128-ctr,aes192-ctr,aes256-ctr

    If no lines are returned, or the returned ciphers list contains any cipher
not starting with \"aes\", this is a finding.
  "
  desc  'fix', "
    Configure the Ubuntu operating system to allow the SSH daemon to only
implement DoD-approved encryption.

    Edit the SSH daemon configuration \"/etc/ssh/sshd_config\" and remove any
ciphers not starting with \"aes\" and remove any ciphers ending with \"cbc\".
If necessary, append the \"Ciphers\" line to the \"/etc/ssh/sshd_config\"
document.

    Ciphers aes128-ctr,aes192-ctr,aes256-ctr

    In order for the changes to take effect, the SSH daemon must be restarted.

    # sudo systemctl restart sshd.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag gid: 'V-219307'
  tag rid: 'SV-219307r508662_rule'
  tag stig_id: 'UBTU-18-010411'
  tag fix_id: 'F-21031r305250_fix'
  tag cci: ['SV-109941', 'V-100837', 'CCI-000068']
  tag nist: ['AC-17 (2)']

  @ciphers_array = inspec.sshd_config.params['ciphers']

  @ciphers_array = @ciphers_array.first.split(',') unless @ciphers_array.nil?

  describe @ciphers_array do
    it { should be_in %w[aes128-ctr aes192-ctr aes256-ctr] }
  end
end

