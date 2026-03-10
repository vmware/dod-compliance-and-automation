control 'VCFB-9X-000025' do
  title 'The VMware Cloud Foundation SDDC Manager NGINX server must protect the .htpasswd file from unauthorized access.'
  desc  'Even though basic authentication is disabled by default, the credentials for its use should be secured and protected from any unauthorized access.'
  desc  'rationale', ''
  desc  'check', "
    Verify file permissions on the .htpasswd file.

    At the command line, run the following:

    # stat -c \"%n permisions are %a, is owned by %U and group owned by %G\" /etc/nginx/.htpasswd

    Example output:

    /etc/nginx/.htpasswd permisions are 640, is owned by root and group owned by nginx

    If the \"/etc/nginx/.htpasswd\" file is not owned by root or group nginx or permissions are more permissive than 640, this is a finding.

    If the \"/etc/nginx/.htpasswd\" file does not exist, this is not applicable.
  "
  desc 'fix', "
    At the command line, run the following:

    # chown root:nginx /etc/nginx/.htpasswd
    # chmod 640 /etc/nginx/.htpasswd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000015'
  tag gid: 'V-VCFB-9X-000025'
  tag rid: 'SV-VCFB-9X-000025'
  tag stig_id: 'VCFB-9X-000025'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  htpasswd = file('/etc/nginx/.htpasswd')

  if htpasswd.exist?
    describe htpasswd do
      it { should_not be_more_permissive_than('0640') }
      its('owner') { should cmp 'root' }
      its('group') { should cmp 'nginx' }
    end
  else
    impact 0.0
    describe 'The file /etc/nginx/.htpasswd does not exist so this is N.A.' do
      skip 'The file /etc/nginx/.htpasswd does not exist so this is N.A.'
    end
  end
end
