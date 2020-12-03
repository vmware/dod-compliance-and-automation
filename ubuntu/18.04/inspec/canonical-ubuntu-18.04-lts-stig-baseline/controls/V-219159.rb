control 'V-219159' do
  title "The Ubuntu operating system must deploy Endpoint Security for Linux Threat
  Prevention (ENSLTP)."
  desc "Without the use of automated mechanisms to scan for security flaws on a continuous and/or
    periodic basis, the operating system or other system components may remain vulnerable to the
    exploits presented by undetected software flaws.

    To support this requirement, the Ubuntu operating system may have an integrated solution
    incorporating continuous scanning using HBSS and periodic scanning using other tools, as specified
    in the requirement.
  "

  impact 0.5
  tag "gtitle": "SRG-OS-000191-GPOS-00080"
  tag "gid": 'V-219159'
  tag "rid": "SV-219159r379093_rule"
  tag "stig_id": "UBTU-18-010021"
  tag "fix_id": "F-20883r304806_fix"
  tag "cci": [ "CCI-001233" ]
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
  desc 'check', "Verify the Ubuntu operating system deploys ENSLTP.

    Check that the following package has been installed:

    # dpkg -l | grep isectp

    If the \"isectp\" package is not installed, this is a finding.

    Check that the daemon is running:

    # ps -ef | grep isectpd

    root 7614 1 2 08:20 ? 00:00:02 /opt/isec/ens/threatprevention/bin/isectpd

    If the daemon is not running, then this is a finding.
  "
  desc 'fix', "Configure the Ubuntu operating system to use ENSLTP.

    Install the isectp package,

    # sudo apt-get install isectp
  "

  describe 'Not Applicable' do
    skip 'Other alternatives for endpoint threat prevention'
  end
end
