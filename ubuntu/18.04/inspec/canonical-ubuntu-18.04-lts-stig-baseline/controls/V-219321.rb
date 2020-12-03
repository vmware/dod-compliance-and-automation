control "V-219321" do
  title "The Ubuntu operating system must only allow the use of DoD PKI-established
    certificate authorities for verification of the establishment of protected sessions."
  desc "Untrusted Certificate Authorities (CA) can issue certificates, but they may
    be issued by organizations or individuals that seek to compromise DoD systems or by
    organizations with insufficient security controls. If the CA used for verifying the
    certificate is not a DoD-approved CA, trust of this CA has not been established.

    The DoD will only accept PKI-certificates obtained from a DoD-approved internal or
    external certificate authority. Reliance on CAs for the establishment of secure
    sessions includes, for example, the use of SSL/TLS certificates.
  "

  impact 0.5
  tag "gtitle": "SRG-OS-000403-GPOS-00182"
  tag "gid": "V-219321"
  tag "rid": "SV-219321r380056_rule"
  tag "stig_id": "UBTU-18-010436"
  tag "fix_id": "F-21045r305292_fix"
  tag "cci": [ "CCI-002470" ]
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
  desc "check", "Verify the directory containing the root certificates for
    the Ubuntu operating system only contains certificate files for DoD PKI-established
    certificate authorities by iterating over all files in the '/etc/ssl/certs' directory and
    checking if, at least one, has the subject matching \"DOD ROOT CA\".

    If none is found, this is a finding.
  "
  desc "fix", "Add at least one DOD certificate authority to the
    '/usr/local/share/ca-certificates' directory, then run the
    'update-ca-certificates' command.
  "

  dod_ca_path = input("dod_ca_path")

  describe x509_certificate(dod_ca_path) do
    its('subject.CN') { should include "DoD Root CA" }
  end
end
