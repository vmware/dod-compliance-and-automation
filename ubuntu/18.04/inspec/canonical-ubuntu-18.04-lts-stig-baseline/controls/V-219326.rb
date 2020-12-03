control 'V-219326' do
  title "The Ubuntu operating system must disable account identifiers (individuals,
    groups, roles, and devices) after 35 days of inactivity."
  desc  "Inactive identifiers pose a risk to systems and applications because
    attackers may exploit an inactive identifier and potentially obtain undetected
    access to the system. Owners of inactive accounts will not notice if
    unauthorized access to their user account has been obtained.

    Ubuntu operating systems need to track periods of inactivity and disable
    application identifiers after 35 days of inactivity.
  "
  impact 0.5
  tag "gtitle": "SRG-OS-000118-GPOS-00060"
  tag "gid": 'V-219326'
  tag "rid": "SV-219326r378880_rule"
  tag "stig_id": "UBTU-18-010445"
  tag "fix_id": "F-21050r305307_fix"
  tag "cci": [ "CCI-000795" ]
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
  desc 'check', "Verify the account identifiers (individuals, groups, roles, and devices) are
    disabled after 35 days of inactivity with the following command:

    Check the account inactivity value by performing the following command:

    # sudo grep INACTIVE /etc/default/useradd

    INACTIVE=35

    If \"INACTIVE\" is not set to a value 0[VALUE]=35, or is commented out, this is a finding.
  "
  desc 'fix', "Configure the Ubuntu operating system to disable account identifiers after
    35 days of inactivity after the password expiration.

    Run the following command to change the configuration for adduser:

    # sudo useradd -D -f 35

    Note: DoD recommendation is 35 days, but a lower value is acceptable. The value \"0\" will
    disable the account immediately after the password expires.
  "
  max_account_inactive_days = input('max_account_inactive_days')
  config_file = '/etc/default/useradd'
  config_file_exists = file(config_file).exist?

  if config_file_exists
    describe parse_config_file(config_file) do
      its('INACTIVE') { should cmp > '0' }
      its('INACTIVE') { should cmp <= max_account_inactive_days }
    end
  else
    describe (config_file + ' exists') do
      subject { config_file_exists }
      it { should be true }
    end
  end
end
