control "VCPG-67-000019" do
  title "The DBMS must provide non-privileged users with error messages that
provide information necessary for corrective actions without revealing
information that could be exploited by adversaries."
  desc  "Any DBMS or associated application providing too much information in
error messages on the screen or printout risks compromising the data and
security of the system. The structure and content of error messages need to be
carefully considered by the organization and development team.

    Databases can inadvertently provide a wealth of information to an attacker
through improperly handled error messages. In addition to sensitive business or
personal information, database errors can provide host names, IP addresses,
user names, and other system information not required for troubleshooting but
very useful to someone targeting the system.

    Carefully consider the structure/content of error messages. The extent to
which information systems are able to identify and handle error conditions is
guided by organizational policy and operational requirements. Information that
could be exploited by adversaries includes, for example, logon attempts with
passwords entered by mistake as the username, mission/business information that
can be derived from (if not stated explicitly by) information recorded, and
personal information, such as account numbers, social security numbers, and
credit card numbers."
  tag component: "postgres"
  tag severity: nil
  tag gtitle: "SRG-APP-000266-DB-000162"
  tag gid: nil
  tag rid: "VCPG-67-000019"
  tag stig_id: "VCPG-67-000019"
  tag cci: "CCI-001312"
  tag nist: ["SI-11 a", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

# grep \"client_min_messages\" /storage/db/vpostgres/postgresql.conf

If there is no output, this is not a finding. If there is output and
'client_min_messages' is not set to 'notice', this is a finding."
  desc 'fix', "Navigate to and open /storage/db/vpostgres/postgresql.conf.

Find the 'client_min_messages' setting and set it to 'notice'."

  describe.one do
    describe parse_config_file('/storage/db/vpostgres/postgresql.conf') do
      its('client_min_messages') { should cmp nil }
    end
    describe parse_config_file('/storage/db/vpostgres/postgresql.conf') do
      its('client_min_messages') { should cmp "notice" }
    end
  end

end

