control "PHTN-10-000036" do
  title "The Photon operating system must disable new accounts immediately upon
password expiration."
  desc  "Inactive identifiers pose a risk to systems and applications because
attackers may exploit an inactive identifier and potentially obtain undetected
access to the system. Owners of inactive accounts will not notice if
unauthorized access to their user account has been obtained.

    Disabling inactive accounts ensures that accounts which may not have been
responsibly removed are not available to attackers who may have compromised
their credentials."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000118-GPOS-00060"
  tag gid: nil
  tag rid: "PHTN-10-000036"
  tag stig_id: "PHTN-10-000036"
  tag cci: "CCI-000795"
  tag nist: ["IA-4 e", "Rev_4"]
  desc 'check', "At the command line, execute the following command:

# grep INACTIVE /etc/default/useradd

Expected result:

INACTIVE=0

If the output does not match the expected result, this is a finding."
  desc 'fix', "Open /etc/default/useradd with a text editor. Remove and existing
\"INACTIVE\" line and add the following line:

INACTIVE=0"

  describe parse_config_file("/etc/default/useradd") do
      its('INACTIVE') { should eq '0'}
  end

end

