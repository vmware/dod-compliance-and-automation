control 'PSQL-00-000028' do
  title 'Database software, including PostgreSQL configuration files, must be stored in dedicated directories separate from the host OS and other applications.'
  desc  "
    When dealing with change control issues, it should be noted any changes to the hardware, software, and/or firmware components of the information system and/or application can potentially have significant effects on the overall security of the system.

    Multiple applications can provide a cumulative negative effect. A vulnerability and subsequent exploit to one application can lead to an exploit of other applications sharing the same security context. For example, an exploit to a web server process that leads to unauthorized administrative access to host system directories can most likely lead to a compromise of all applications hosted by the same system. Database software not installed using dedicated directories both threatens and is threatened by other hosted applications. Access controls defined for one application may by default provide access to the other application's database objects or directories. Any method that provides any level of separation of security context assists in the protection between applications.
  "
  desc  'rationale', ''
  desc  'check', "
    Review the PostgreSQL software directory and any subdirectories.

    Only applications that are required for the functioning and administration, not use, of PostgreSQL should be located in the same disk directory as the PostgreSQL installation.

    If other applications are located in the same directory as PostgreSQL, this is a finding.
  "
  desc 'fix', 'Install all applications on directories separate from the PostgreSQL installation and/or configuration directory. Relocate any directories or reinstall other application software that currently shares the PostgreSQL installation directory.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000133-DB-000199'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PSQL-00-000028'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']

  describe 'Review the PostgreSQL software directory and any subdirectories for other applications in the same directory.' do
    skip 'This is a manual check...Review the PostgreSQL software directory and any subdirectories for other applications in the same directory.'
  end
end
