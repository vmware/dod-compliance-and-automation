control 'CFPG-4X-000017' do
  title 'The SDDC Manager PostgreSQL service must not allow schema access to unauthorized accounts.'
  desc  "
    An isolation boundary provides access control and protects the integrity of the hardware, software, and firmware that perform security functions.

    Security functions are the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based.

    Developers and implementers can increase the assurance in security functions by employing well-defined security policy models; structured, disciplined, and rigorous hardware and software development techniques; and sound system/security engineering principles.

    Database Management Systems typically separate security functionality from non-security functionality via separate databases or schemas. Database objects or code implementing security functionality should not be commingled with objects or code implementing application logic. When security and non-security functionality are commingled, users who have access to non-security functionality may be able to access security functionality.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # psql -h localhost -U postgres -c \"\\dp *.*\" | grep -E \"information_schema|pg_catalog\" | awk -F '|' '{print $4}'|awk -F '/' '{print $1}' | grep -v \"=r\" | grep -v \"postgres\" | grep -v \"^[[:space:]]*$\"

    If any lines are returned, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following command:

    # psql -h localhost -U postgres -c \"REVOKE ALL PRIVILEGES ON <name> FROM <user>;\"

    Replace <name> and <user> with the Access Privilege name and account, respectively, discovered during the check.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000233-DB-000124'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'CFPG-4X-000017'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']

  describe command("psql -h localhost -U postgres -c \"\dp *.*\" | grep -E \"information_schema|pg_catalog\" | awk -F '|' '{print $4}'|awk -F '/' '{print $1}' | grep -v \"=r\" | grep -v \"postgres\" | grep -v \"^[[:space:]]*$\"").stdout do
    it { should cmp '' }
  end
end
