control 'VRPE-8X-000007' do
  title 'The VMware Aria Operations Apache server expansion modules must be fully reviewed, tested, and signed.'
  desc  "
    In the case of a production web server, areas for content development and testing will not exist, as this type of content is only permissible on a development website.  The process of developing on a functional production website entails a degree of trial and error and repeated testing.  This process is often accomplished in an environment where debugging, sequencing, and formatting of content are the main goals.  The opportunity for a malicious user to obtain files that reveal business logic and login schemes is high in this situation.  The existence of such immature content on a web server represents a significant security risk that is totally avoidable.

    The web server must enforce, internally or through an external utility, the signing of modules before they are implemented into a production environment.  By signing modules, the author guarantees that the module has been reviewed and tested before production implementation.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, run the following command:

    # grep LoadModule /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf | grep -v '^#'

    Expected result:

    LoadModule   jk_module       /usr/lib64/httpd/modules/mod_jk.so
    LoadModule   rewrite_module  /usr/lib64/httpd/modules/mod_rewrite.so
    LoadModule   headers_module  /usr/lib64/httpd/modules/mod_headers.so
    LoadModule   http2_module    /usr/lib64/httpd/modules/mod_http2.so
    LoadModule deflate_module /usr/lib64/httpd/modules/mod_deflate.so

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Open /usr/lib/vmware-vcopssuite/utilities/conf/vcops-apache.conf in a text editor.

    Ensure the following are the only 'LoadModule' lines present:

    LoadModule   jk_module       /usr/lib64/httpd/modules/mod_jk.so
    LoadModule   rewrite_module  /usr/lib64/httpd/modules/mod_rewrite.so
    LoadModule   headers_module  /usr/lib64/httpd/modules/mod_headers.so
    LoadModule   http2_module    /usr/lib64/httpd/modules/mod_http2.so
    LoadModule deflate_module /usr/lib64/httpd/modules/mod_deflate.so

    Save and close.

    At the command prompt, run the following command:

    # systemctl restart httpd
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000131-WSR-000073'
  tag satisfies: ['SRG-APP-000141-WSR-000082']
  tag gid: 'V-VRPE-8X-000007'
  tag rid: 'SV-VRPE-8X-000007'
  tag stig_id: 'VRPE-8X-000007'
  tag cci: ['CCI-000381', 'CCI-001749']
  tag nist: ['CM-5 (3)', 'CM-7 a']

  mods = input('modules')
  conf = apache_conf(input('apacheConfPath'))

  # compare without spaces
  conf.params['LoadModule'].each do |item|
    matchfound = false
    mods.each do |mod|
      next unless item.gsub(' ', '').eql?(mod.gsub(' ', ''))
      matchfound = true
      describe 'Evaluating LoadModule config' do
        subject { item.gsub(' ', '') }
        it { should cmp mod.gsub(' ', '') }
      end
    end

    next if matchfound
    describe item do
      it { should be_in mods }
    end
  end
end
