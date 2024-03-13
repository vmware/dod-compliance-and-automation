control 'WOAT-3X-000039' do
  title 'Workspace ONE Access must not have any unexpected symbolic links in the web content directory tree.'
  desc  "A web server is designed to deliver content and execute scripts or applications on the request of a client or user. Containing user requests to files in the directory tree of the hosted web application and limiting the execution of scripts and applications guarantees that the user is not accessing information protected outside the application's realm. By checking that no symbolic links exist in the document root, the web server is protected from users jumping outside the hosted application directory tree and gaining access to the other directories, including the system root."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # find /opt/vmware/horizon/workspace/webapps/ -type l -ls|awk '{print $11 \" \" $12 \" \" $13;}'

    Expected result:

    /opt/vmware/horizon/workspace/webapps/ROOT/horizon_workspace_rootca.pem -> /etc/ssl/certs/horizon_service_tcserver.pem

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    At the command prompt, execute the following command:

    Note: Replace <file_name> for the name of any files that were returned.

    unlink <file_name>

    Repeat the command for each file that was returned.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000087'
  tag gid: 'V-WOAT-3X-000039'
  tag rid: 'SV-WOAT-3X-000039'
  tag stig_id: 'WOAT-3X-000039'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe command('find /opt/vmware/horizon/workspace/webapps/ -type l -ls') do
    its('stdout.strip') { should match %r{/opt/vmware/horizon/workspace/webapps/ROOT/horizon_workspace_rootca.pem -> /etc/ssl/certs/horizon_service_tcserver.pem} }
  end
end
