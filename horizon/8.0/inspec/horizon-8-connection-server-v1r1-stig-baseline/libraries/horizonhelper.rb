class HorizonHelper < Inspec.resource(1)
  name 'horizonhelper'
  @@generatedtoken = nil
  @@websessionPS = nil
  @@parms = {}
  @@transport = nil
  @@transportlocal = nil
  @@horizonsession = nil

  def promptpass
    if @@parms['password'].nil?
      @@parms['password'] = STDIN.getpass('Enter Password: ').chomp
    end
  end

  def promptuser
    if @@parms['user'].nil?
      puts 'Enter Username: '
      @@parms['user'] = STDIN.gets.chomp
    end
  end

  def prompthost
    if @@parms['fqdn'].nil?
      puts 'Enter Host FQDN or IP: '
      @@parms['fqdn'] = STDIN.gets.chomp
    end
  end

  def promptdomain
    if @@parms['domain'].nil?
      puts 'Enter Domain Name: '
      @@parms['domain'] = STDIN.gets.chomp
    end
  end

  ################################################################################################################################
  # ORDER OF OPERATIONS
  # 1. CLI --t or --transport (with --user and --password) --> let InSpec create the transport, use provided, prompt for missing
  # 2. CLI --input (fqdn=blah, user=blah, etc)             --> Use provided, prompt for missing
  # 3. CLI --input-file                                    --> parse file for inputs
  # 4. None or some of the above                           --> prompt for missing inputs
  #
  # REQUIRED Parameters:
  # -user         (available off transport, or as an input variable at the cli, in inspec.yml, or in --input-file)
  # -fqdn (or IP) (available as an input variable at the cli, in inspec.yml, or in --input-file) - don't want to
  #                 try to parse the transport as it could be IP or FQDN - too many options with dots.
  # -password     (available off transport, or as an input variable at the cli, in inspec.yml, or in --input-file)
  # -domain       (available off transport, or as an input variable at the cli, in inspec.yml, or in --input-file)
  #
  ################################################################################################################################

  def parseinputs
    # Parse command line arguments (must be first, in case they pass in --input-file)
    parseargs()
    # Parse --input-file(s) if they provided any - will only 'add' values, and not 'overwrite' if it's already there
    parseinputfile()
    # Parse inspec.yml file from profile - will only 'add' values, and not 'overwrite' if it's already there
    parseinspecinputs()
    # Prompt for any missing 'required' params
    promptuser()
    promptpass()
    prompthost()
    promptdomain()
  end

  def parseargs
    # Create key/value pairs, parse command line args out...
    i = 0
    until i >= (ARGV.length - 1)
      if ['-t', '--t', '-transport', '--transport'].include?(ARGV[i])
        i += 1
        @@parms['transport'] = ARGV[i]
      elsif ['-user', '--user'].include?(ARGV[i])
        i += 1
        @@parms['user'] = ARGV[i]
      elsif ['-password', '--password'].include?(ARGV[i])
        i += 1
        @@parms['password'] = ARGV[i]
      elsif ['-input-file', '--input-file'].include?(ARGV[i])
        # add until end, or next '-' or '--' is found...
        found = true
        filelist = []
        until !found
          i += 1
          if i >= ARGV.length || ARGV[i].start_with?('-')
            found = false
          else
            filelist.push(ARGV[i])
          end
        end
        @@parms['inputfiles'] = filelist
      elsif ['-input', '--input'].include?(ARGV[i])
        # add until end, or next '-' or '--' is found...
        found = true
        until !found
          i += 1
          if i >= ARGV.length || ARGV[i].start_with?('-')
            found = false
          else
            tmp = ARGV[i].split('=')
            @@parms[tmp[0]] = tmp[1]
            if tmp[0] == 'runlocal'
              puts 'Using local transport'
              @@transport = 'local'
            end
          end
        end
      end
      i += 1
    end
  end

  def parseinputfile
    unless @@parms['inputfiles'].nil?
      @@parms['inputfiles'].each do |fl|
        tmp = YAML.load_file(fl)
        # Check if any of our expected inputs is included in the file
        ['fqdn', 'domain', 'user', 'password'].each do |poss|
          next if tmp[poss].nil?
          # Only add it if it's not there (order of ops)
          next unless @@parms[poss].nil?
          @@parms[poss] = tmp[poss]
        end
      end
    end
  end

  def parseinspecinputs
    tmp = YAML.load_file('inspec.yml')
    # puts tmp.inspect
    tmpvals = tmp['inputs'].map { |hash| hash.values_at('name', 'value') }.to_h
    # Check if any of our expected inputs is included in the file
    ['fqdn', 'domain', 'user', 'password'].each do |poss|
      next if tmpvals[poss].nil?
      # Only add it if it's not there (order of ops)
      next unless @@parms[poss].nil?
      @@parms[poss] = tmpvals[poss]
    end
  end

  def gettoken
    if @@generatedtoken.nil?
      generatetoken
    end
    @@generatedtoken
  end

  def getsessionpowershell
    if @@websessionPS.nil?
      generatesessionpowershell
    end
    @@websessionPS
  end

  def generatetoken
    begin
      if @@parms == {}
        parseinputs
      end
      setconnection
      # First chunk is for self-signed certs... probably don't need for 'official', but can't get a token without it
      # Doing the array -Join method to get around the Powershell Here-String formatting issue (indentation)
      pscmd = <<-EOH
        $pol =
          @('using System.Net; using System.Security.Cryptography.X509Certificates;'
          'public class TrustAllCertsPolicy : ICertificatePolicy'
          '{ public bool CheckValidationResult(ServicePoint s, X509Certificate c, WebRequest r, int p) { return true; } }'
          ) -Join [Environment]::NewLine
        Add-Type $pol
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        $Parameters = @{
          Method = 'Post'
          Uri = 'https://#{@@parms['fqdn']}/rest/login'
          ContentType = 'application/json'
          Body = @{
            domain   = '#{@@parms['domain']}'
            username = '#{@@parms['user']}'
            password = '#{@@parms['password']}'
          } | ConvertTo-Json
        }
        Invoke-RestMethod @Parameters | ConvertTo-Json
      EOH
      result = inspec.powershell(pscmd)
      if !result.stderr.empty?
        puts 'ERRORS: ' + result.stderr
        @@generatedtoken = nil
      else
        json = JSON.parse(result.stdout)
        @@generatedtoken = json['access_token']
      end
    rescue StandardError => e
      puts "Exception Class: #{e.class.name}"
      puts "Exception Message: #{e.message}"
      # puts "Exception Backtrace: #{ e.backtrace }"
    end
  end

  def generatesessionpowershell
    begin
      if @@parms == {}
        parseinputs
      end
      setconnection
      pscmd = <<-EOH
        $pol =
          @('using System.Net; using System.Security.Cryptography.X509Certificates;'
            'public class TrustAllCertsPolicy : ICertificatePolicy'
            '{ public bool CheckValidationResult(ServicePoint s, X509Certificate c, WebRequest r, int p) { return true; } }'
            ) -Join [Environment]::NewLine
          Add-Type $pol
          [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        $Parameters = @{
          Method = 'Post'
          Uri = 'https://#{@@parms['fqdn']}/view-vlsi/rest/v1/login'
          ContentType = 'application/json'
          Body = @{
            domain   = '#{@@parms['domain']}'
            name = '#{@@parms['user']}'
            passwd = '#{@@parms['password']}'
          } | ConvertTo-Json
        }
        $response = Invoke-WebRequest @Parameters -SessionVariable result
        $c = $result.Cookies.GetCookies('https://#{@@parms['fqdn']}/view-vlsi/rest/v1/login')[0]
        $r = New-Object PSObject | Select-Object CSRFToken, Name, Path, Value, Domain, Secure, HttpOnly
        $r.CSRFToken = $response.Headers.CSRFToken
        $r.Name = $c.Name
        $r.Path = $c.Path
        $r.Value = $c.Value
        $r.Domain = $c.Domain
        $r.Secure = $c.Secure
        $r.HttpOnly = $c.HttpOnly
        $r | ConvertTo-Json
      EOH
      result = inspec.powershell(pscmd)
      if !result.stderr.empty?
        puts 'ERRORS: ' + result.stderr
        @@websessionPS = nil
      else
        json = JSON.parse(result.stdout)
        @@websessionPS = <<-EOH
          $cookie=new-object system.net.cookie
          $cookie.name = '#{json['Name']}'
          $cookie.path = '#{json['Path']}'
          $cookie.value = '#{json['Value']}'
          $cookie.Domain = '#{json['Domain']}'
          $cookie.Secure = $#{json['Secure']}
          $cookie.HttpOnly = $#{json['HttpOnly']}
          $session=new-object microsoft.powershell.commands.webrequestsession
          $session.cookies.add($cookie)
          $session.headers.add('CSRFToken', '#{json['CSRFToken']}')
        EOH
      end
    rescue StandardError => e
      puts "Exception Class: #{e.class.name}"
      puts "Exception Message: #{e.message}"
      # puts "Exception Backtrace: #{ e.backtrace }"
    end
  end

  def getpowershellrestwithsession(restendpoint)
    pscmd = <<-EOH
      $Parameters = @{
        Method = 'GET'
        Uri = 'https://#{@@parms['fqdn']}/#{restendpoint}'
        ContentType = 'application/json'
      }
      #{getsessionpowershell}
      Invoke-RestMethod @Parameters -websession $session | ConvertTo-Json
    EOH
    inspec.powershell(pscmd)
  end

  def postpowershellrestwithsession(restendpoint, body)
    pscmd = <<-EOH
      $Parameters = @{
        Method = 'POST'
        Uri = 'https://#{@@parms['fqdn']}/#{restendpoint}'
        ContentType = 'application/json'
        Body = '#{body}'
      }
      #{getsessionpowershell}
      Invoke-RestMethod @Parameters -websession $session | ConvertTo-Json
    EOH
    inspec.powershell(pscmd)
  end

  def getpowershellrestwithtoken(restendpoint)
    pscmd = <<-EOH
      $Parameters = @{
        Method = 'GET'
        Uri = 'https://#{@@parms['fqdn']}/#{restendpoint}'
        ContentType = 'application/json'
        Headers = @{
          Authorization = 'Bearer #{gettoken}'
          Accept = 'application/json'
        }
      }
      Invoke-RestMethod @Parameters | ConvertTo-Json
    EOH
    inspec.powershell(pscmd)
  end

  def getinput(keyname)
    if @@parms == {}
      parseinputs
    end
    @@parms[keyname]
  end

  def setconnection
    # Only manually create the transport if they did not define it at the command line
    if @@parms == {}
      parseinputs
    end

    if @@transport.nil?
      puts 'Creating winrm transport...'
      @@transport = Train.create(
        'winrm',
        host: "#{@@parms['fqdn']}",
        user: "#{@@parms['user']}",
        password: "#{@@parms['password']}",
        ssl: false,
        self_signed: true
      ).connection
      inspec.backend = @@transport
    end
  end

  def setconnectionlocal
    # Only manually create the transport if they did not define it at the command line
    if @@parms == {}
      parseinputs
    end
    if @@transportlocal.nil?
      @@transportlocal = Train.create('local').connection
    end
    #   localconn = @@transportlocal.connection
    #   if localconn.nil?
    #     raise 'Could not create local transport'
    #   else
    #     puts 'Local Transport Created --> ' + localconn.os.name
    #   end
    # else
    #   #puts 'Using native InSpec transport creator'
    # end
    inspec.backend = @@transportlocal
  end

  def runlocalcommand(cmd)
    if @@parms == {}
      parseinputs
    end
    if @@transportlocal.nil?
      @@transportlocal = Train.create('local').connection
    end
    puts 'Running local command on: ' + @@transportlocal.os.name
    @@transportlocal.run_command(cmd)
  end

  def runremotecommand(cmd)
    if @@parms == {}
      parseinputs
    end
    if @@transport.nil?
      @@transport = Train.create(
        'winrm',
        host: "#{@@parms['fqdn']}",
        user: "#{@@parms['user']}",
        password: "#{@@parms['password']}",
        ssl: false,
        self_signed: true
      ).connection
    end
    puts 'Running command on: ' + @@transport.os.name
    @@transport.run_command(cmd)
  end

  def connecthorizonserver
    begin
      if @@parms == {}
        parseinputs
      end
      if @@horizonsession.nil?
        pscmd = <<-EOH
          $Parameters = @{
            Server = '#{@@parms['fqdn']}'
            Domain = '#{@@parms['domain']}'
            User = '#{@@parms['user']}'
            Password = '#{@@parms['password']}'
          }
          Connect-HVServer @Parameters | Select SessionSecret | ConvertTo-Json
        EOH
        result = inspec.powershell(pscmd)
        if !result.stderr.empty?
          puts 'ERRORS: ' + result.stderr
          @@horizonsession = nil
        else
          json = JSON.parse(result.stdout)
          @@horizonsession = json['SessionSecret']
          puts 'Session ID generated - ' + @@horizonsession
        end
      else
        puts 'Using existing Session ID - ' + @@horizonsession
      end
    rescue StandardError => e
      puts "Exception Class: #{e.class.name}"
      puts "Exception Message: #{e.message}"
      # puts "Exception Backtrace: #{ e.backtrace }"
    end
  end

  def run_local_powershell(cmd)
    setconnectionlocal
    pscmd = <<-EOH
          $Parameters = @{
            Server = '#{@@parms['fqdn']}'
            Domain = '#{@@parms['domain']}'
            User = '#{@@parms['user']}'
            Password = '#{@@parms['password']}'
          }
          $horizon = Connect-HVServer @Parameters
          #{cmd}
        EOH

    inspec.powershell(pscmd)
  end
end
