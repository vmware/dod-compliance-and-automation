control "V-219190" do
  title "The Ubuntu operating system must configure the /var/log directory to be owned by root."
  desc "Only authorized personnel should be aware of errors and the details of the errors.
    Error messages are an indicator of an organization's operational state or can identify
    the operating system or platform. Additionally, Personally Identifiable Information (PII)
    and operational information must not be revealed through error messages to unauthorized
    personnel or their designated representatives.

    The structure and content of error messages must be carefully considered by the
    organization and development team. The extent to which the information system is able to
    identify and handle error conditions is guided by organizational policy and operational
    requirements.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000206-GPOS-00084"
  tag "gid": "V-219190"
  tag "rid": "SV-219190r379108_rule"
  tag "stig_id": "UBTU-18-010123"
  tag "fix_id": "F-20914r304899_fix"
  tag "cci": [ "CCI-001314" ]
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
  desc "check", "	Verify the Ubuntu operating system configures the /var/log directory to
    be owned by root.

    Check that the /var/log directory is owned by root with the following command:

    # sudo stat -c \"%n %U\" /var/log
    /var/log root

    If the /var/log directory is not owned by root, this is a finding.
  "
  desc "fix", "Change the owner of the directory /var/log to root by running the
    following command:

    # sudo chown root /var/log
  "

  describe directory("/var/log") do
    its("owner") { should cmp "root" }
  end
end
