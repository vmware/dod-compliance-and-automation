control 'V-219182' do
  title "The Ubuntu operating system must employ a FIPS 140-2 approved cryptographic
    hashing algorithms for all created and stored passwords."
  desc  "Passwords need to be protected at all times, and encryption is the
    standard method for protecting passwords. If passwords are not encrypted, they
    can be plainly read (i.e., clear text) and easily compromised.

    Unapproved mechanisms that are used for authentication to the cryptographic
    module are not verified and therefore cannot be relied upon to provide
    confidentiality or integrity, and DoD data may be compromised.

    FIPS 140-2 is the current standard for validating that mechanisms used to
    access cryptographic modules utilize authentication that meets DoD requirements.
  "

  impact 0.5
  tag "gtitle": "SRG-OS-000120-GPOS-00061"
  tag "satisfies": nil
  tag "gid": 'V-219182'
  tag "rid": "SV-219182r378886_rule"
  tag "stig_id": "UBTU-18-010110"
  tag "fix_id": "F-20906r304875_fix"
  tag "cci": [ "CCI-000803" ]
  tag "nist": nil
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  desc 'check', "Verify that encrypted passwords stored in /etc/shadow use a strong
    cryptographic hash.

    Check that pam_unix.so auth is configured to use sha512 with the following command:

    # grep password /etc/pam.d/common-password | grep pam_unix

    password [success=1 default=ignore] pam_unix.so obscure sha512

    If \"sha512\" is not an option of the output, or is commented out, this is a finding.

    Check that ENCRYPT_METHOD is set to sha512 in /etc/login.defs:

    # grep -i ENCRYPT_METHOD /etc/login.defs

    ENCRYPT_METHOD SHA512

    If the output does not contain \"sha512\", or it is commented out, this is a finding.
  "

  desc 'fix', "Configure the Ubuntu operating system to encrypt all stored passwords with a
    strong cryptographic hash.

    Edit/modify the following line in the file \"/etc/pam.d/common-password\" file to include
    the sha512 option for pam_unix.so:

    password [success=1 default=ignore] pam_unix.so obscure sha512

    Edit/modify /etc/login.defs and set \"ENCRYPT_METHOD sha512\".
  "

  describe login_defs do
    its('ENCRYPT_METHOD') { should eq 'SHA512' }
  end
end
