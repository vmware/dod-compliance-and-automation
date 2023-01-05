control 'CFNG-4X-000023' do
  title 'The SDDC Manager NGINX service must disable server side includes.'
  desc  'Disabling server side includes prevents the exploitation of the web server by preventing the potentional injection of scripts and remote code execution through the SSI functionality.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command:

    # nginx -T 2>&1 | sed -n \"/^http\\s{/,/server\\s{/p\" | grep \"ssi \"

    Expected result:

    ssi off;

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    The nginx.conf (/etc/nginx/nginx.conf by default) file.

    Add the following line in the http context:

    ssi off;

    At the command line, run the following command:

    # nginx -s reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'CFNG-4X-000023'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe.one do
    describe nginx_conf_custom(input('nginx_conf_path')).params['http'][0]['ssi'] do
      it { should include ['off'] }
    end
    describe nginx_conf_custom(input('nginx_conf_path')).params['http'][0]['ssi'] do
      it { should be nil }
    end
  end
end
