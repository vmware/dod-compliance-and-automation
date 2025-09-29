control 'NGNX-WB-000035' do
  title 'NGINX must protect system resources and privileged operations from hosted applications.'
  desc  'Running a web server under a non-privileged, dedicated service account helps mitigate the risk of lateral movement to other services or processes in the event the user account running the web services is compromised. The default user nobody is typically used for several processes, and if this is compromised, it could allow an attacker to have access to all processes running as that user'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command:

    # nginx -T 2>&1 | grep \"^user\"

    Example result:

    user www-data www-data;

    If the user directive is not set, this is a finding.
  "
  desc 'fix', "
    Establish a non-privileged account to run NGINX worker processes.

    This account should no be a part of any unneeded groups, have sudo access, or the ability to login interactively.

    Navigate to and open:

    The nginx.conf (/etc/nginx/nginx.conf by default) file.

    Add the following line in the main context at the top of the file:

    user <username> <groupname>;

    Reload the NGINX configuration by running the following command:

    # nginx -s reload

    Note: If the group is not the same as the user name it can be specified in this format, user <username> <group>;.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000086'
  tag gid: 'V-NGNX-WB-000035'
  tag rid: 'SV-NGNX-WB-000035'
  tag stig_id: 'NGNX-WB-000035'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  nginx_user = input('nginx_user')
  nginx_group = input('nginx_group')
  user_dir = nginx_conf_custom(input('nginx_conf_path')).params['user']
  user = user_dir.flatten[0]
  group = user_dir.flatten[1]

  if user
    describe user do
      it { should cmp nginx_user }
    end
  else
    describe user do
      it { should_not be nil }
    end
  end

  if group
    describe group do
      it { should cmp nginx_group }
    end
  end
end
