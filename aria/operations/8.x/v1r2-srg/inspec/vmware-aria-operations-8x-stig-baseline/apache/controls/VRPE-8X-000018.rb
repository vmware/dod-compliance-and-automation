control 'VRPE-8X-000018' do
  title 'The vRealize Operations Manager Apache server warning and error messages displayed to clients must be modified to minimize the identity of the web server, patches, loaded modules, and directory paths.'
  desc  "
    Information needed by an attacker to begin looking for possible vulnerabilities in a web server includes any information about the web server, backend systems being accessed, and plug-ins or modules being used.

    Web servers will often display error messages to end users containing enough information to aid in the debugging of the error. The information given back in error messages may display the web server type, version, patches installed, plug-ins and modules installed, type of code being used by the hosted application, and any backends being used for data storage.

    This information could be used by an attacker to blueprint what type of attacks might be successful. The information given to users must be minimized to not aid in the blueprinting of the web server.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # grep ServerSignature /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf | grep -v '^#'

    Expected result:

    ServerSignature Off

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf

    Add or configure the following lines:

    ServerSignature Off

    Save and close.

    At the command prompt, run the following command:

    # systemctl restart httpd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000266-WSR-000159'
  tag gid: 'V-VRPE-8X-000018'
  tag rid: 'SV-VRPE-8X-000018'
  tag stig_id: 'VRPE-8X-000018'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']

  describe apache_conf(input('apacheConfPath')) do
    its('ServerSignature') { should cmp 'off' }
  end
end
