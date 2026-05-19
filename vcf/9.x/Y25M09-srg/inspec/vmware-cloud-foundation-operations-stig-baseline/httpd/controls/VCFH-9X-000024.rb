control 'VCFH-9X-000024' do
  title 'The VMware Cloud Foundation Operations Apache HTTP service must not perform user management for hosted applications.'
  desc  "
    User management and authentication can be an essential part of any application hosted by the web server. Along with authenticating users, the user management function must perform several other tasks like password complexity, locking users after a configurable number of failed logins, and management of temporary and emergency accounts; and all of this must be done enterprise-wide.

    The web server contains a minimal user management function, but the web server user management function does not offer enterprise-wide user management, and user management is not the primary function of the web server. User management for the hosted applications should be done through a facility that is built for enterprise-wide user management, like LDAP and Active Directory.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the server is not performing user management functions.

    At the command prompt, run the following:

    # grep -i \"AuthUserFile\" /etc/httpd/conf/httpd.conf /etc/httpd/conf/extra/httpd-ssl.conf /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf

    If there is any output indicating the server is performing user management, this is a finding.
  "
  desc 'fix', "
    Navigate to the file found with the \"AuthUserFile\" directive and remove it.

    Reload the configuration by running the following command:

    # systemctl reload httpd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000015'
  tag gid: 'V-VCFH-9X-000024'
  tag rid: 'SV-VCFH-9X-000024'
  tag stig_id: 'VCFH-9X-000024'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  conf = input('apache_httpd_conf_file')

  # Make sure the conf file exists so the tests do not pass with false positives
  describe file(conf) do
    it { should exist }
  end
  describe 'AuthUserFile' do
    subject { apache_conf_custom(conf).AuthUserFile }
    it { should be nil }
  end
end
