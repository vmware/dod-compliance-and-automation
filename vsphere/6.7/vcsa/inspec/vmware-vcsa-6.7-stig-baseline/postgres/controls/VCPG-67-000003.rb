control "VCPG-67-000003" do
  title "The vPostgres configuration file must not be accessible by
unauthorized users."
  desc  "Without the capability to restrict which roles and individuals can
select which events are audited, unauthorized personnel may be able to prevent
or interfere with the auditing of critical events.

    Suppression of auditing could permit an adversary to evade detection.

    Misconfigured audits can degrade the system's performance by overwhelming
the audit log. Misconfigured audits may also make it more difficult to
establish, correlate, and investigate the events relating to an incident or
identify those responsible for one."
  tag component: "postgres"
  tag severity: nil
  tag gtitle: "SRG-APP-000090-DB-000065"
  tag gid: nil
  tag rid: "VCPG-67-000003"
  tag stig_id: "VCPG-67-000003"
  tag cci: "CCI-000171"
  tag nist: ["AU-12 b", "Rev_4"]
  desc 'check', "At the command prompt, enter the following command:

# stat -c \"%n permissions are %a\" /storage/db/vpostgres/*conf*

If the permissions on any of the listed files are not \"600\", this is a
finding."
  desc 'fix', "At the command prompt, enter the following command:

# chmod 600 <file>

Note: Replace <file> with the file with incorrect permissions."

  command('find /storage/db/vpostgres/ -type f -maxdepth 1 -name "*conf*"').stdout.split.each do | fname |
    describe file(fname) do
      its('mode') { should cmp '0600' }
    end
  end

end

