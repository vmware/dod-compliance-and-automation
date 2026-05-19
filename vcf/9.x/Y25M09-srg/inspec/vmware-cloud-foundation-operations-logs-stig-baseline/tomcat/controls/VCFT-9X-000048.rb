control 'VCFT-9X-000048' do
  title 'The VMware Cloud Foundation Operations for Logs Loginsight service must protect access to the web server private key.'
  desc  "
    The cornerstone of PKI is the private key used to encrypt or digitally sign information.

    If the private key is stolen, this will lead to the compromise of the authentication and non-repudiation gained through PKI because the attacker can use the private key to digitally sign documents and can pretend to be the authorized user.

    Both the holders of a digital certificate and the issuing authority must protect the computers, storage devices, or whatever they use to keep the private keys. Java-based application servers utilize the Java keystore, which provides storage for cryptographic keys and certificates. The keystore is usually maintained in a file stored on the file system.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following:

    # stat -c \"%n permissions are %a, is owned by %U and group owned by %G\" /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/keystore.bcfks

    Example result:

    /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/keystore.bcfks permissions are 600, is owned by root and group owned by root

    If the keystore file is not owned by \"root\" with permissions of \"600\" or more restrictive, this is a finding.

    Note: The \"keystore.bcfks\" file does not exist unless FIPS mode is enabled. If FIPS mode is not enabled replace \"keystore.bcfks\" with \"keystore\".
  "
  desc 'fix', "
    At the command prompt, run the following:

    # chmod 600 /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/keystore.bcfks
    # chown root:root /usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/keystore.bcfks
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000176-AS-000125'
  tag satisfies: ['SRG-APP-000915-AS-000310']
  tag gid: 'V-VCFT-9X-000048'
  tag rid: 'SV-VCFT-9X-000048'
  tag stig_id: 'VCFT-9X-000048'
  tag cci: ['CCI-000186', 'CCI-004910']
  tag nist: ['IA-5 (2) (a) (1)', 'SC-28 (3)']

  describe file('/usr/lib/loginsight/application/3rd_party/apache-tomcat/conf/keystore.bcfks') do
    it { should_not be_more_permissive_than('0600') }
    its('owner') { should cmp 'root' }
    its('group') { should cmp 'root' }
  end
end
