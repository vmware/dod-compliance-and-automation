control 'VCFJ-9X-000034' do
  title 'The VMware Cloud Foundation Operations HCX Apache HTTP service must protect system resources and privileged operations from hosted applications.'
  desc  "
    A web server may host one to many applications.  Each application will need certain system resources and privileged operations to operate correctly.  The web server must be configured to contain and control the applications and protect the system resources and privileged operations from those not needed by the application for operation.

    Limiting the application will confine the potential harm a compromised application could cause to a system.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the service is run as a nonprivileged and dedicated service account.

    At the command prompt, run the following:

    # grep -i -E \"User|Group\" /etc/httpd/conf/httpd.conf /opt/vmware/config/apache-httpd/hcx-ssl.conf /opt/vmware/config/apache-httpd/hcx-virtual-hosts.conf

    Example output:

    User admin
    Group secureall

    If \"User\" is configured to \"root\" or \"0\", this is a finding.

    If \"Group\" is configured to \"root\" or \"0\", this is a finding.

    If the \"User\" or \"Group\" is configured with an account that is not dedicated to running the service or has more privileges than needed, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/httpd/conf/httpd.conf

    Note: If the offending configuration was found in a different file edit that file instead.

    Add or update the \"User\" and/or \"Group\" directives with a dedicated service account.

    User admin
    Group secureall

    Restart the service by running the following command:

    # systemctl restart httpd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000086'
  tag gid: 'V-VCFJ-9X-000034'
  tag rid: 'SV-VCFJ-9X-000034'
  tag stig_id: 'VCFJ-9X-000034'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  conf = input('apache_httpd_conf_file')

  # Make sure the conf file exists so the tests do not pass with false positives
  describe file(conf) do
    it { should exist }
  end
  describe apache_conf_custom(conf) do
    its('User') { should_not cmp 'root' }
    its('User') { should_not cmp '0' }
    its('Group') { should_not cmp 'root' }
    its('Group') { should_not cmp '0' }
  end
end
