control 'VRPE-8X-000020' do
  title 'Debugging and trace information used to diagnose the VMware Aria Operations Apache server must be disabled.'
  desc  "
    Information needed by an attacker to begin looking for possible vulnerabilities in a web server includes any information about the web server and plug-ins or modules being used.

    When debugging or trace information is enabled in a production web server, information about the web server, such as web server type, version, patches installed, plug-ins and modules installed, type of code being used by the hosted application, and any backends being used for data storage may be displayed.

    Because this information may be placed in logs and general messages during normal operation of the web server, an attacker does not need to cause an error condition to gain this information.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # grep TraceEnable /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf | grep -v '^#'

    Expected result:

    TraceEnable off

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf

    Add or configure the following lines:

    TraceEnable off

    Save and close.

    At the command prompt, run the following command:

    # systemctl restart httpd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000266-WSR-000160'
  tag gid: 'V-VRPE-8X-000020'
  tag rid: 'SV-VRPE-8X-000020'
  tag stig_id: 'VRPE-8X-000020'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']

  describe apache_conf(input('apacheConfPath')) do
    its('TraceEnable') { should cmp 'off' }
  end
end
