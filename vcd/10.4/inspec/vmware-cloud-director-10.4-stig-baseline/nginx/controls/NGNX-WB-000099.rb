control 'NGNX-WB-000099' do
  title 'NGINX must disable server side includes.'
  desc  'Disabling server side includes prevents the exploitation of the web server by preventing the potential injection of scripts and remote code execution through the SSI functionality.'
  desc  'rationale', ''
  desc  'check', "
    Verify server side includes are off.

    View the running configuration by running the following command:

    # nginx -T 2>&1 | grep \"ssi\"

    Example configuration:

    http {
      ssi off;
    }

    If the the directive \"ssi\" is configured and set to on, this is a finding.

    If the directive \"ssi\" is not configured, this is NOT a finding.

    Note: The \"ssi\" directive is off by default if not explicitly defined.
  "
  desc 'fix', "
    Navigate to and open:

    The nginx.conf (/etc/nginx/nginx.conf by default or the included file where the directive was configured) file.

    Remove the \"ssi on;\" statement.

    Reload the NGINX configuration by running the following command:

    # nginx -s reload
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'NGNX-WB-000099'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  command('nginx -T 2>&1 | grep "ssi "').stdout.split.each do |result|
    describe result do
      it { should cmp 'ssi off;' }
    end
  end
end
