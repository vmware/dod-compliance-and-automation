control 'CFSS-4X-000003' do
  title 'The SDDC Manager SOS service must not have any symbolic links in its directory to outside directories.'
  desc  "A web server is designed to deliver content and execute scripts or applications on the request of a client or user.  Containing user requests to files in the directory tree of the hosted web application and limiting the execution of scripts and applications guarantees that the user is not accessing information protected outside the application's realm."
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # find /opt/vmware/sddc-support/ -type l -ls

    If the command produces for symbolic links outside this directory, this is a finding.
  "
  desc 'fix', "
    At the command prompt, run the following command:

    # unlink <file_name>

    Repeat the commands for each file that was returned.

    Note: Replace <file_name> for the name of any files that were returned.
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-APP-000141-WSR-000087'
  tag gid: 'V-CFSS-4X-000003'
  tag rid: 'SV-CFSS-4X-000003'
  tag stig_id: 'CFSS-4X-000003'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  results = command('find /opt/vmware/sddc-support/ -type l -ls')
  if results.stdout != ''
    results.stdout.split("\n").each do |fname|
      describe fname do
        it { should match %r{->\s/opt/vmware/sddc-support} }
      end
    end
  else
    describe results.stdout do
      it { should cmp '' }
    end
  end
end
