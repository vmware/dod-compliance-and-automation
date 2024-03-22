control 'TCSV-00-000048' do
  title 'tc Server must only allow authorized system administrators to have access to the keystore.'
  desc  "
    The tc Server's private key is used to prove the identity of the server to clients and securely exchange the shared secret key used to encrypt communications between the server and clients.

    By gaining access to the private key, an attacker can pretend to be an authorized server and decrypt the SSL traffic between a client and the server.

    The default .keystore file location is the home folder of the user account used to run tc Server, although some administrators may choose to place the file elsewhere. The location will also be specified in the server.xml file.
  "
  desc  'rationale', ''
  desc  'check', "
    Identify the location of the .keystore file. Refer to system documentation or review the server.xml file for a specified .keystore file location.

    At the command prompt, run the following command:

    # xmllint --xpath \"//Certificate/@certificateKeystoreFile | //Connector/@keystoreFile\" $CATALINA_BASE/conf/server.xml | awk 1 RS=' '

    For each file path returned, check the file permissions by running the command below:

    # ls -la [keystorefile location]

    Verify that file permissions are set to “640” or more restrictive.

    Verify that the owner and group-owner are set according to system requirements. If either of these conditions are not met, this is a finding.
  "
  desc 'fix', "
    At the command prompt, execute the following commands:

    # chmod 640 [keystorefile location]
    # chown tomcat [keystorefile location]
    # chgrp tomcat [keystorefile location]

    Note: The user and group name tomcat is used here as a reference, but technically can be named anything.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000176-AS-000125'
  tag gid: 'V-TCSV-00-000048'
  tag rid: 'SV-TCSV-00-000048'
  tag stig_id: 'TCSV-00-000048'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (b)']

  if file(input('keystoreFile')).exist?
    describe file(input('keystoreFile')) do
      its('owner') { should eq "#{input('svcAccountName')}" }
      its('group') { should eq "#{input('svcGroup')}" }
      it { should_not be_more_permissive_than('0640') }
    end
  else
    describe 'Keystore File not defined or not found' do
      skip 'No Keystore File found'
    end
  end
end
