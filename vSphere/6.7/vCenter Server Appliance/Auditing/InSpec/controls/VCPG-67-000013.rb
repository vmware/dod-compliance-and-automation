control "VCPG-67-000013" do
  title "The vPostgres database must be configured to use ssl."
  desc  "The DoD standard for authentication is DoD-approved PKI certificates.

    Authentication based on User ID and Password may be used only when it is
not possible to employ a PKI certificate, and requires AO approval.

    In such cases, passwords need to be protected at all times, and encryption
is the standard method for protecting passwords during transmission.

    DBMS passwords sent in clear text format across the network are vulnerable
to discovery by unauthorized users. Disclosure of passwords may easily lead to
unauthorized access to the database.
  "
  tag component: "postgres"
  tag severity: nil
  tag gtitle: "SRG-APP-000172-DB-000075"
  tag gid: nil
  tag rid: "VCPG-67-000013"
  tag stig_id: "VCPG-67-000013"
  tag fix_id: nil
  tag cci: "CCI-000197"
  tag nist: ["IA-5 (1) (c)", "Rev_4"]
  tag false_negatives: nil
  tag false_positives: nil
  tag documentable: nil
  tag mitigations: nil
  tag severity_override_guidance: nil
  tag potential_impacts: nil
  tag third_party_tools: nil
  tag mitigation_controls: nil
  tag responsibility: nil
  tag ia_controls: "IA-5 (1) (c)"
  tag check: "At the command prompt, execute the following command:

# grep '^\\s*ssl\\b' /storage/db/vpostgres/postgresql.conf

If \"ssl\" is not \"on\", this is a finding."
  tag fix: "At the command prompt, execute the following commands:

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"ALTER SYSTEM SET ssl
TO 'on';\"

# /opt/vmware/vpostgres/current/bin/psql -U postgres -c \"SELECT
pg_reload_conf();\""

  describe parse_config_file('/storage/db/vpostgres/postgresql.conf') do
    its('ssl') { should eq "on" }
  end

end

