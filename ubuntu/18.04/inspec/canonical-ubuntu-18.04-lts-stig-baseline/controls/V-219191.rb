control "V-219191" do
  title "The Ubuntu operating system must configure the /var/log directory to have mode 0750
    or less permissive."
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
  tag "gid": "V-219191"
  tag "rid": "SV-219191r379108_rule"
  tag "stig_id": "UBTU-18-010124"
  tag "fix_id": "F-20915r304902_fix"
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
  desc "check", "Verify that the \"/var/log\" directory has a mode of \"0750\" or less.

    Check the mode of the \"/var/log\" directory with the following command:

    # stat -c \"%a %n\" /var/log

    770

    If a value of \"0750\" or less permissive is not returned, this is a finding.
  "

  desc "fix", "Change the permissions of the directory \"/var/log\" to \"0750\" by running
    the following command:

    # sudo chmod 0750 /var/log
  "

  describe directory("/var/log") do
    it { should_not be_more_permissive_than("0750") }
  end
end
