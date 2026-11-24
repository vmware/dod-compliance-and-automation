control 'VCFB-9X-000035' do
  title 'The VMware Cloud Foundation SDDC Manager NGINX server worker process must be run as a nonprivileged user.'
  desc  'Running a web server under a nonprivileged, dedicated service account helps mitigate the risk of lateral movement to other services or processes in the event the user account running the web services is compromised. The default user "nobody" is typically used for several processes, and if this account is compromised, it could allow an attacker to have access to all processes running as that user'
  desc  'rationale', ''
  desc  'check', "
    Verify the NGINX server's worker processes are configured to run as a nonprivileged user.

    At the command line, run the following:

    # nginx -V

    Example result:

    user nginx nginx;

    Or if no data is returned, run the following to check if the user was specified as an argument when compiled:

    # nginx -V 2>&1

    Review the output for the \"--user\" and \"--group\" arguments.

    If the \"user\" directive is not set to a nonprivileged user, this is a finding.
  "
  desc 'fix', "
    Establish a nonprivileged account to run NGINX worker processes.

    This account should not be a part of any unneeded groups, have sudo access, or have the ability to login interactively.

    Navigate to and open:

    The nginx.conf (/etc/nginx/nginx.conf by default) file.

    Add the following line in the main context at the top of the file:

    user nginx;

    Reload the NGINX configuration by running the following command:

    # nginx -s reload

    Note: If the group is not the same as the user name it can be specified in this format, user <username> <group>;.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000086'
  tag gid: 'V-VCFB-9X-000035'
  tag rid: 'SV-VCFB-9X-000035'
  tag stig_id: 'VCFB-9X-000035'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  nginx_user = input('nginx_user')
  nginx_group = input('nginx_group')
  user_dir = nginx_conf_custom(input('nginx_conf_path')).params['user']
  userarg = nginx_custom(input('nginx_bin_path')).user
  grouparg = nginx_custom(input('nginx_bin_path')).group
  userfound = false

  if user_dir
    user = user_dir.flatten[0]
    group = user_dir.flatten[1]
    userfound = true
    describe 'NGINX user directive' do
      subject { user }
      it { should cmp nginx_user }
    end
    unless !group
      describe 'NGINX group directive specified' do
        subject { group }
        it { should cmp nginx_group }
      end
    end
  elsif userarg
    userfound = true
    describe 'NGINX user argument' do
      subject { userarg }
      it { should cmp nginx_user }
    end
    unless !grouparg
      describe 'NGINX group argument specified' do
        subject { grouparg }
        it { should cmp nginx_group }
      end
    end
  end
  unless userfound
    describe 'No user directive or arugment found.' do
      subject { userfound }
      it { should be true }
    end
  end
end
