control 'V-219343' do
  title "The Ubuntu operating system must use a file integrity tool to verify
    correct operation of all security functions."
  desc  "Without verification of the security functions, security functions may
not operate correctly and the failure may go unnoticed. Security function is
defined as the hardware, software, and/or firmware of the information system
responsible for enforcing the system security policy and supporting the
    isolation of code and data on which the protection is based. Security
    functionality includes, but is not limited to, establishing system accounts,
configuring access authorizations (i.e., permissions, privileges), setting
events to be audited, and setting intrusion detection parameters.

    This requirement applies to Ubuntu operating systems performing security
    function verification/testing and/or systems and environments that require this
    functionality.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000445-GPOS-00199"
  tag "gid": 'V-219343'
  tag "rid": "SV-219343r380293_rule"
  tag "stig_id": "UBTU-18-010515"
  tag "fix_id": "F-21067r305358_fix"
  tag "cci": [ "CCI-002696" ]
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
  desc 'check', "Verify that Advanced Intrusion Detection Environment (AIDE) is
    installed and verifies the correct operation of all security functions.

    Check that the AIDE package is installed with the following command:

    # sudo dpkg -l | grep aide

    aide/xenial,now 0.16~a2.git20130520-3 amd64 [installed]

    If AIDE is not installed, ask the System Administrator how file integrity
    checks are performed on the system.

    If there is no application installed to perform integrity checks,
    this is a finding.
  "
  desc 'fix', "Install the AIDE package by running the following command:

    # sudo apt-get install aide
  "
  describe package('aide') do
    it { should be_installed }
  end
end
