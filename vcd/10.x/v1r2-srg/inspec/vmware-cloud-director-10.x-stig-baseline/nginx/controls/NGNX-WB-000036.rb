control 'NGNX-WB-000036' do
  title 'NGINX must not have any symbolic links that traverse outside the web content directory tree.'
  desc  "
    A web server is designed to deliver content and execute scripts or applications on the request of a client or user.  Containing user requests to files in the directory tree of the hosted web application and limiting the execution of scripts and applications guarantees that the user is not accessing information protected outside the application's realm.

    The web server must also prohibit users from jumping outside the hosted application directory tree through access to the user's home directory, symbolic links or shortcuts, or through search paths for missing files.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify web content directories do not contain symbolic links that traverse outside the web content directory tree.

    View the defined root directories by running the following command:

    # nginx -T 2>&1 | grep root

    Example output:

    root /opt/mywebsite/www;

    For each root directive, run the following command:

    # find /opt/mywebsite/www/ -type l -ls

    If the any symbolic links are defined that traverse outside the root web directory, this is a finding.
  "
  desc  'fix', "
    Any content referenced through a symbolic link outside of the root web directory should be moved into the root web directory.

    To remove a symbolic link, run the following command:

    # unlink <file_name>

    Repeat the command for each file that was returned.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000087'
  tag satisfies: ['SRG-APP-000233-WSR-000146']
  tag gid: 'V-NGNX-WB-000036'
  tag rid: 'SV-NGNX-WB-000036'
  tag stig_id: 'NGNX-WB-000036'
  tag cci: ['CCI-000381', 'CCI-001084']
  tag nist: ['CM-7 a', 'SC-3']

  http_block_root = nginx_conf_custom(input('nginx_conf_path')).params['http'][0]['root']
  servers = nginx_conf_custom(input('nginx_conf_path')).servers
  locations = nginx_conf_custom(input('nginx_conf_path')).locations

  # Check http block for root directives
  if !http_block_root.nil?
    http_block_root = http_block_root.flatten[0]
    if File.directory?(http_block_root)
      describe command("find #{http_block_root}/ -type l") do
        its('stdout') { should cmp '' }
      end
    else
      describe command("find /usr/share/nginx/#{http_block_root}/ -type l") do
        its('stdout') { should cmp '' }
      end
    end
  else
    describe 'No http root block directive' do
      skip 'No http root block directive...skipping...'
    end
  end

  # Check server blocks for root directives
  if !servers.nil?
    servers.each do |server|
      server_root = server.params['root']
      next unless server_root
      server_root = server_root.flatten[0]
      if File.directory?(server_root)
        describe command("find #{server_root}/ -type l") do
          its('stdout') { should cmp '' }
        end
      else
        describe command("find /usr/share/nginx/#{server_root}/ -type l") do
          its('stdout') { should cmp '' }
        end
      end
    end
  else
    describe 'No server root block directive' do
      skip 'No server root block directive...skipping...'
    end
  end

  # Check location blocks for root directives
  if !locations.nil?
    locations.each do |location|
      location_root = location.params['root']
      next unless location_root
      location_root = location_root.flatten[0]
      if File.directory?(location_root)
        describe command("find #{location_root}/ -type l") do
          its('stdout') { should cmp '' }
        end
      else
        describe command("find /usr/share/nginx/#{location_root}/ -type l") do
          its('stdout') { should cmp '' }
        end
      end
    end
  else
    describe 'No location root block directive' do
      skip 'No location root block directive...skipping...'
    end
  end
end
