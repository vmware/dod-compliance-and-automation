control 'VRPE-8X-000027' do
  title 'The vRealize Operations Manager Apache server must secure MIME types.'
  desc  "
    Configuring the web server to implement organization-wide security implementation guides and security checklists guarantees compliance with federal standards and establishes a common security baseline across the DoD that reflects the most restrictive security posture consistent with operational requirements.

    Configuration settings are the set of parameters that can be changed that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the web server, including the parameters required to satisfy other security control requirements.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # grep -E \"nosniff\" /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf | grep -v '^#'

    Expected result:

    Header set X-Content-Type-Options \"nosniff\"

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf

    Add or configure the following line:

    Header set X-Content-Type-Options \"nosniff\"

    Save and close.

    At the command prompt, run the following command:

    # systemctl restart httpd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag gid: 'V-VRPE-8X-000027'
  tag rid: 'SV-VRPE-8X-000027'
  tag stig_id: 'VRPE-8X-000027'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe command("grep -E 'nosniff' #{input('apacheConfPath')} | grep -v '^#'") do
    its('stdout.strip') { should cmp 'Header set X-Content-Type-Options "nosniff"' }
  end
end
