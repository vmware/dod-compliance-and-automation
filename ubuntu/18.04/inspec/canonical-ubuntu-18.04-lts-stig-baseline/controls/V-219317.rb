control 'V-219317' do
  title "The Ubuntu operating system must implement smart card logins for
    multifactor authentication for access to accounts."
  desc  "Using an authentication device, such as a CAC or token that is
    separate from the information system, ensures that even if the information
    system is compromised, that compromise will not affect credentials stored on
    the authentication device.

    Multifactor solutions that require devices separate from information
    systems gaining access include, for example, hardware tokens providing
    time-based or challenge-response authenticators and smart cards such as the
    U.S. Government Personal Identity Verification card and the DoD Common Access
    Card.

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
  impact 0.5
  tag "gtitle": "SRG-OS-000105-GPOS-00052"
  tag "satisfies": nil

  tag "gid": 'V-219317'
  tag "rid": "SV-219317r378850_rule"
  tag "stig_id": "UBTU-18-010427"
  tag "fix_id": "F-21041r305280_fix"
  tag "cci": [ "CCI-000765","CCI-000766","CCI-000767","CCI-000768","CCI-001954" ]
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
  desc 'check', "Verify the Ubuntu operating system uses multifactor authentication
    for local access to accounts.

    Check that the \"pam_pkcs11.so\" option is configured in the \"/etc/pam.d/common-auth\"
    file with the following command:

    # grep pam_pkcs11.so /etc/pam.d/common-auth
    auth [success=2 default=ignore] pam_pkcs11.so

    If \"pam_pkcs11.so\" is not set in \"/etc/pam.d/common-auth\", this is a finding.
  "
  desc 'fix', "Configure the Ubuntu operating system to use multifactor authentication
    for local access to accounts.

    Add or update \"pam_pkcs11.so\" in \"/etc/pam.d/common-auth\" to match the following line:

    auth [success=2 default=ignore] pam_pkcs11.so
  "
  describe command('grep pam_pkcs11.so /etc/pam.d/common-auth') do
    its('stdout') { should_not be_empty }
  end
end
