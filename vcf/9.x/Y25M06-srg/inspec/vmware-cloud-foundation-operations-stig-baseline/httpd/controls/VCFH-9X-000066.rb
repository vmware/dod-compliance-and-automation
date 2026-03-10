control 'VCFH-9X-000066' do
  title 'The VMware Cloud Foundation Operations Apache HTTP service must minimize the identity of the web server.'
  desc  "
    Information needed by an attacker to begin looking for possible vulnerabilities in a web server includes any information about the web server, backend systems being accessed, and plug-ins or modules being used.

    Web servers will often display error messages to client users displaying enough information to aid in the debugging of the error. The information given back in error messages may display the web server type, version, patches installed, plug-ins and modules installed, type of code being used by the hosted application, and any backends being used for data storage.

    This information could be used by an attacker to blueprint what type of attacks might be successful. The information given to users must be minimized to not aid in the blueprinting of the web server.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify server information is not displayed on error messages or headers.

    At the command prompt, run the following:

    # grep -i -E \"ServerTokens|ServerSignature\" /etc/httpd/conf/httpd.conf /etc/httpd/conf/extra/httpd-ssl.conf /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf

    Example output:

    ServerSignature Off
    ServerTokens Prod

    If the value of \"ServerSignature\" is set to \"On\", this is a finding.

    If \"ServerSignature\" does not exist or is commented out, this is not a finding.

    If the value of \"ServerTokens\" is not set to \"Prod\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf

    Note: If the offending configuration was found in a different file edit that file instead.

    Add or update the following lines:

    ServerSignature Off
    ServerTokens Prod

    Reload the configuration by running the following command:

    # systemctl reload httpd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000266-WSR-000159'
  tag gid: 'V-VCFH-9X-000066'
  tag rid: 'SV-VCFH-9X-000066'
  tag stig_id: 'VCFH-9X-000066'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']

  conf = input('apache_httpd_conf_file')

  # Make sure the conf file exists so the tests do not pass with false positives
  describe file(conf) do
    it { should exist }
  end
  if apache_conf_custom(conf).ServerSignature.nil?
    describe 'ServerSignature' do
      subject { apache_conf_custom(conf).ServerSignature }
      it { should be nil }
    end
  else
    describe apache_conf_custom(conf) do
      its('ServerSignature') { should_not cmp 'On' }
    end
  end
  if apache_conf_custom(conf).ServerTokens.nil?
    describe 'ServerTokens' do
      subject { apache_conf(conf).ServerTokens }
      it { should_not be_nil }
    end
  else
    describe apache_conf_custom(conf) do
      its('ServerTokens') { should cmp 'Prod' }
    end
  end
end
