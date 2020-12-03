control 'V-219337' do
  title 'The Ubuntu operating system must enable and run the uncomplicated firewall(ufw).'
  desc  "Firewalls protect computers from network attacks by blocking or
    limiting access to open network ports. Application firewalls limit which
    applications are allowed to communicate over the network."
  impact 0.5
  tag "gtitle": "SRG-OS-000297-GPOS-00115"
  tag "gid": 'V-219337'
  tag "rid": "SV-219337r379450_rule"
  tag "stig_id": "UBTU-18-010507"
  tag "fix_id": "F-21061r305340_fix"
  tag "cci": [ "CCI-002314" ]
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
  desc 'check', "Verify the Uncomplicated Firewall is enabled on the system by running the following command:

    # systemctl is-enabled ufw

    If the above command returns the status as \"disabled\", this is a finding.

    Verify the Uncomplicated Firewall is active on the system by running the following command:

    # sudo systemctl is-active ufw

    If the above command returns 'inactive' or any kind of error, this is a finding.

    If the Uncomplicated Firewall is not installed ask the System Administrator if
    another application firewall is installed.

    If no application firewall is installed this is a finding.
  "
  desc 'fix', "Enable the Uncomplicated Firewall by using the following command:

    # sudo systemctl enable ufw.service

    If the Uncomplicated Firewall is not currently running on the system, start it with the following command:

    # sudo systemctl start ufw.service
  "
  describe service('ufw') do
    it { should be_installed }
    it { should be_enabled }
    it { should be_running }
  end
end
