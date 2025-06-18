control 'VCFJ-9X-000040' do
  title 'The VMware Cloud Foundation Operations HCX Apache HTTP service must use FIPS validated cryptographic modules.'
  desc  "
    Encryption is only as good as the encryption modules utilized.  Unapproved cryptographic module algorithms cannot be verified, and cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised due to weak algorithms.

    FIPS 140-2 is the current standard for validating cryptographic modules and NSA Type-X (where X=1, 2, 3, 4) products are NSA-certified, hardware-based encryption modules.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the \"SSLFIPS\" setting is enabled.

    At the command prompt, run the following:

    # grep -i \"SSLFIPS\" /etc/httpd/conf/httpd.conf /opt/vmware/config/apache-httpd/hcx-ssl.conf /opt/vmware/config/apache-httpd/hcx-virtual-hosts.conf /etc/httpd/conf/fips.conf

    Example output:

    SSLFIPS ON

    If the value of \"SSLFIPS\" is set to \"off\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/httpd/conf/fips.conf

    Note: If the offending configuration was found in a different file edit that instead.

    Add or update the following lines:

    SSLFIPS ON

    Restart the service by running the following command:

    # systemctl restart httpd
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000179-WSR-000110'
  tag satisfies: ['SRG-APP-000179-WSR-000111', 'SRG-APP-000224-WSR-000135', 'SRG-APP-000224-WSR-000136', 'SRG-APP-000416-WSR-000118', 'SRG-APP-000439-WSR-000188']
  tag gid: 'V-VCFJ-9X-000040'
  tag rid: 'SV-VCFJ-9X-000040'
  tag stig_id: 'VCFJ-9X-000040'
  tag cci: ['CCI-000803', 'CCI-001188', 'CCI-002418', 'CCI-002450']
  tag nist: ['IA-7', 'SC-13 b', 'SC-23 (3)', 'SC-8']

  conf = input('apache_httpd_conf_file')

  # Make sure the conf file exists so the tests do not pass with false positives
  describe file(conf) do
    it { should exist }
  end
  if apache_conf_custom(conf).SSLFIPS.nil?
    describe 'No SSLFIPS directive found and' do
      subject { apache_conf_custom(conf).SSLFIPS }
      it { should_not be_nil }
    end
  else
    describe apache_conf_custom(conf) do
      its('SSLFIPS') { should cmp 'ON' }
    end
  end
end
