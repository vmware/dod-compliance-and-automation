control 'TCSV-00-000105' do
  title 'tc Server must be patched for security vulnerabilities.'
  desc  'tc Server is constantly being updated to address newly discovered vulnerabilities, some of which include denial-of-service attacks. To address this risk, the administrator must ensure the system remains up to date on patches.'
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # $JAVA_HOME/bin/java -cp /usr/lib/loginsight/application/lib/web-tomcat-li.jar org.apache.catalina.util.ServerInfo

    Compare the version running on the system to the latest secure version.

    If the latest secure version of tc Server is not installed, this is a finding.
  "
  desc 'fix', "
    Follow operational procedures for upgrading tc Server. Download latest version of tc Server and install in a test environment. Test applications that are running in production and follow all operations best practices when upgrading the production tc Server application servers.

    Update the tc Server production instance accordingly and ensure corrected builds are installed once tested and verified.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000435-AS-000163'
  tag gid: 'V-TCSV-00-000105'
  tag rid: 'SV-TCSV-00-000105'
  tag stig_id: 'TCSV-00-000105'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5']

  # No easy way to get the tomcat version - call up the serverinfo jar
  describe command("#{input('javaHome')} -cp /usr/lib/loginsight/application/lib/web-tomcat-li.jar org.apache.catalina.util.ServerInfo") do
    its('stdout') { should include input('tcVersion') }
  end
end
