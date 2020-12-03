control 'V-219157' do
  title 'The Ubuntu operating system must not have the Network Information Service
    (NIS) package installed.'
  desc  "Removing the Network Information Service (NIS) package decreases the
    risk of the accidental (or intentional) activation of NIS or NIS+ services.
  "
  impact 0.8
  tag "gtitle": "SRG-OS-000095-GPOS-00049"
  tag "gid": 'V-219157'
  tag "rid": "SV-219157r378841_rule"
  tag "stig_id": "UBTU-18-010018"
  tag "fix_id": "F-20881r304800_fix"
  tag "cci": [ "CCI-000381" ]
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
  desc 'check', "Verify that the Network Information Service (NIS) package is not
    installed on the Ubuntu operating system.

    Check to see if the NIS package is installed with the following command:

    # dpkg -l | grep nis

    If the NIS package is installed, this is a finding.
  "

  desc 'fix', "Configure the Ubuntu operating system to disable non-essential capabilities
    by removing the Network Information Service (NIS) package from the system with the
    following command:

    # sudo apt-get remove nis
  "
  describe package('nis') do
    it { should_not be_installed }
  end
end
