control 'V-219177' do
  title 'The Ubuntu operating system must not have the telnet package installed.'
  desc  "It is detrimental for Ubuntu operating systems to provide, or install
    by default, functionality exceeding requirements or mission objectives. These
    unnecessary capabilities or services are often overlooked and therefore may
    remain unsecured. They increase the risk to the platform by providing
    additional attack vectors.

    Ubuntu operating systems are capable of providing a wide variety of
    functions and services. Some of the functions and services, provided by
    default, may not be necessary to support essential organizational operations
    (e.g., key missions, functions).

    Examples of non-essential capabilities include, but are not limited to,
    games, software packages, tools, and demonstration software, not related to
    requirements or providing a wide array of functionality not required for every
    mission, but which cannot be disabled.
  "
  impact 0.8
  tag "gtitle": "SRG-OS-000074-GPOS-00042"
  tag "satisfies": nil
  tag "gid": 'V-219177'
  tag "rid": "SV-219177r378754_rule"
  tag "stig_id": "UBTU-18-010105"
  tag "fix_id": "F-20901r304860_fix"
  tag "cci": [ "CCI-000197" ]
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
  desc 'check', "Verify that the telnet package is not installed on the Ubuntu operating system.

    Check that the telnet daemon is not installed on the Ubuntu operating system by running
    the following command:

    # dpkg -l | grep telnetd

    If the package is installed, this is a finding.
  "
  desc 'fix', "Remove the telnet package from the Ubuntu operating system by running the
    following command:

    # sudo apt-get remove telnetd
  "
  describe package('telnetd') do
    it { should_not be_installed }
  end
end
