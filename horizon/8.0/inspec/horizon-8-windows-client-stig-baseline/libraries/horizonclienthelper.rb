class HorizonClientHelper < Inspec.resource(1)
  name 'horizonclienthelper'
  @@parms = {}
  @@transport = nil
  @@local = false

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

    unless @@local
      # Prompt for any missing 'required' params
      promptuser()
      promptpass()
      prompthost()
    end
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
              @@local = true
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

    if @@parms['transport'].nil?
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
  end
end
