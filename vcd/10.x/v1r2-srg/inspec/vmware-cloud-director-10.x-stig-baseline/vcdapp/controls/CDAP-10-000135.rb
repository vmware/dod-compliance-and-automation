control 'CDAP-10-000135' do
  title 'Cloud Director must enable host header verification.'
  desc  "
    HTTP response splitting occurs when:

    Data enters a web application through an untrusted source, most frequently an HTTP request or the data is included in an HTTP response header sent to a web user without being validated for malicious characters.

    HTTP response splitting is a means to an end, not an end in itself. At its root, the attack is straightforward: an attacker passes malicious data to a vulnerable application, and the application includes the data in an HTTP response header.

    Cloud Director includes a configuration that when enabled prevents host header injection by comparing the host header against an allow list comprised of the allowed origins, the public endpoint, and cell endpoint.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify host header checks are configured by running the following command:

    # /opt/vmware/vcloud-director/bin/cell-management-tool manage-config -n vcloud.http.enableHostHeaderCheck -l

    Expected result:

    Property \"vcloud.http.enableHostHeaderCheck\" has value \"true\"

    If \"vcloud.http.enableHostHeaderCheck\" does not exist or is set to false, this is a finding.
  "
  desc 'fix', "
    At the command prompt, execute the following command:

    # /opt/vmware/vcloud-director/bin/cell-management-tool manage-config -n vcloud.http.enableHostHeaderCheck -v true
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-CDAP-10-000135'
  tag rid: 'SV-CDAP-10-000135'
  tag stig_id: 'CDAP-10-000135'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe command('/opt/vmware/vcloud-director/bin/cell-management-tool manage-config -n vcloud.http.enableHostHeaderCheck -l') do
    its('stdout.strip') { should cmp 'Property "vcloud.http.enableHostHeaderCheck" has value "true"' }
  end
end
