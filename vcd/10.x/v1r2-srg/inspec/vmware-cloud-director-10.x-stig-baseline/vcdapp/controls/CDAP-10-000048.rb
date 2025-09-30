control 'CDAP-10-000048' do
  title 'Cloud Director must restrict access to the web servers private key.'
  desc  "
    The cornerstone of the PKI is the private key used to encrypt or digitally sign information.

    If the private key is stolen, this will lead to the compromise of the authentication and non-repudiation gained through PKI because the attacker can use the private key to digitally sign documents and can pretend to be the authorized user.

    Both the holders of a digital certificate and the issuing authority must protect the computers, storage devices, or whatever they use to keep the private keys. Java-based application servers utilize the Java keystore, which provides storage for cryptographic keys and certificates. The keystore is usually maintained in a file stored on the file system.
  "
  desc  'rationale', ''
  desc  'check', "
    Cloud Director stores key information for services in multiple locations and files which all must have their permissions checked.

    Verify key file permissions by running the following commands on each appliance:

    # find /opt/vmware/vcloud-director/etc/*.key -type f -a '(' -not -perm 0600 -o -not -user vcloud -o -not -group vcloud ')' -exec ls -ls {} \\;
    # find /opt/vmware/appliance/etc/ssl/*.key -type f -a '(' -not -perm 0640 -o -not -user root -o -not -group users ')' -exec ls -ls {} \\;

    If any results are returned, this is a finding.

    Verify properties file by running the following commands on each appliance:

    stat -c \"%n permissions are %a and ownership is %U:%G\" /opt/vmware/vcloud-director/etc/global.properties
    stat -c \"%n permissions are %a and ownership is %U:%G\" /opt/vmware/vcloud-director/etc/responses.properties

    Expected result:

    /opt/vmware/vcloud-director/etc/global.properties permissions are 600 and ownership is vcloud:vcloud
    /opt/vmware/vcloud-director/etc/responses.properties permissions are 640 and ownership is vcloud:vcloud

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    To correct permissions on files under /opt/vmware/vcloud-director/etc run the following commands:

    # chmod 600 <file>
    # chown vcloud:vcloud <file>


    To correct permissions on files under /opt/vmware/appliance/etc/ssl run the following commands:

    # chmod 600 <file>
    # chown root:users <file>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000176-AS-000125'
  tag gid: 'V-CDAP-10-000048'
  tag rid: 'SV-CDAP-10-000048'
  tag stig_id: 'CDAP-10-000048'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']

  command("find /opt/vmware/vcloud-director/etc/ -type f -maxdepth 1 -name '*key'").stdout.split.each do |fname|
    describe file(fname) do
      its('mode') { should cmp '0600' }
      its('owner') { should cmp 'vcloud' }
      its('group') { should cmp 'vcloud' }
    end
  end
  command("find /opt/vmware/appliance/etc/ssl/ -type f -maxdepth 1 -name '*key'").stdout.split.each do |fname|
    describe file(fname) do
      its('mode') { should cmp '0640' }
      its('owner') { should cmp 'root' }
      its('group') { should cmp 'users' }
    end
  end
  describe file('/opt/vmware/vcloud-director/etc/global.properties') do
    its('mode') { should cmp '0600' }
    its('owner') { should cmp 'vcloud' }
    its('group') { should cmp 'vcloud' }
  end
  describe file('/opt/vmware/vcloud-director/etc/responses.properties') do
    its('mode') { should cmp '0600' }
    its('owner') { should cmp 'vcloud' }
    its('group') { should cmp 'vcloud' }
  end
end
