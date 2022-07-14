control 'NGNX-WB-000096' do
  title 'NGINX must remove the default web site configuration.'
  desc  'After installation, an NGINX default website is configured to listen on port 80 and servers a generic page indicating that the NGINX server is working. This page contains information that reveals details about the server and is over an insecure connection and should be removed.'
  desc  'rationale', ''
  desc  'check', "
    Verify the default NGINX web site configuration is not enabled.

    At the command prompt, run the following command:

    # ls -la /etc/nginx/sites-enabled/

    Example output:

    lrwxrwxrwx 1 root root   34 Mar  1 15:18 default -> /etc/nginx/sites-enabled/default

    If the output shows that the default web site is enabled, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following command:

    # rm /etc/nginx/sites-enabled/default

    Reload the NGINX configuration by running the following command:

    # nginx -s reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'NGNX-WB-000096'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  approved_sites = input('approved_sites')

  command('ls /etc/nginx/sites-enabled/').stdout.split.each do |site|
    describe site do
      it { should be_in approved_sites }
    end
  end
end
