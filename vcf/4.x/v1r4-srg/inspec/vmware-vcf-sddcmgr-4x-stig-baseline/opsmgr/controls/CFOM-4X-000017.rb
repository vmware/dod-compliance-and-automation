control 'CFOM-4X-000017' do
  title 'The SDDC Manager Operations Manager service log files must be moved to a permanent repository in accordance with site policy.'
  desc  "
    A web server will typically utilize logging mechanisms for maintaining a historical log of activity that occurs within a hosted application. This information can then be used for diagnostic purposes, forensics purposes, or other purposes relevant to ensuring the availability and integrity of the hosted application.

    While it is important to log events identified as being critical and relevant to security, it is equally important to notify the appropriate personnel in a timely manner so they are able to respond to events as they occur.

    Manual review of the web server logs may not occur in a timely manner, and each event logged is open to interpretation by a reviewer. By integrating the web server into an overall or organization-wide log review, a larger picture of events can be viewed, and analysis can be done in a timely and reliable manner.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # grep -v \"^#\" /etc/rsyslog.d/stig-services-operationsmanager.conf

    Expected result:

    module(load=\"imfile\" mode=\"inotify\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/vcf/operationsmanager/*.log\"
          Tag=\"vcf-operationsmanager-runtime\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/vcf/operationsmanager/upgrades/*/*\"
          Tag=\"vcf-operationsmanager-upgrades\"
          Severity=\"info\"
          Facility=\"local0\")

    If the file does not exist, this is a finding.

    If the output of the command does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/rsyslog.d/stig-services-operationsmanager.conf

    Create the file if it does not exist.

    Set the contents of the file as follows:

    module(load=\"imfile\" mode=\"inotify\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/vcf/operationsmanager/*.log\"
          Tag=\"vcf-operationsmanager-runtime\"
          Severity=\"info\"
          Facility=\"local0\")
    input(type=\"imfile\"
          File=\"/var/log/vmware/vcf/operationsmanager/upgrades/*/*\"
          Tag=\"vcf-operationsmanager-upgrades\"
          Severity=\"info\"
          Facility=\"local0\")

    At the command prompt, run the following command:

    # systemctl restart rsyslog.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000358-WSR-000163'
  tag gid: 'V-CFOM-4X-000017'
  tag rid: 'SV-CFOM-4X-000017'
  tag stig_id: 'CFOM-4X-000017'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']

  goodcontent = inspec.profile.file('stig-services-operationsmanager.conf')
  describe file('/etc/rsyslog.d/stig-services-operationsmanager.conf') do
    its('content') { should eq goodcontent }
  end
end
