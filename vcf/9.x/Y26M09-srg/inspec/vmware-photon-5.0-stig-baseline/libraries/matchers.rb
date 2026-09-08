# TODO: explain somewhere that :all_with_args, :all_without_args, :all_with_integer_arg
# will cause match_pam_rule to return true when there are no potential matches
RSpec::Matchers.define :match_pam_rule do |expected|
  def matching_integer_arg?(line)
    line.module_arguments.any? do |arg|
      key, value = arg.split('=')

      value && (@args[:key] == key) && value.match?(/^-?\d+$/) &&
        value.to_i.send(@args[:operator].to_sym, @args[:value])
    end
  end

  match do |actual|
    case @args_type
    when :all_with_args, :all_without_args, :all_with_integer_arg
      retval = true
    when :any_with_args, :any_with_integer_arg
      retval = false
    end

    if [:all_with_integer_arg, :any_with_integer_arg].include? @args_type
      unless Numeric.method_defined?(@args[:operator])
        raise("Error: Operator '#{@args[:operator]}' is an invalid numeric comparison operator.")
      end
    end

    actual_munge = {}

    @expected = expected.to_s

    if @args_type
      catch :stop_searching do
        actual.services.each do |service|
          expected_line = Pam::Rule.new(expected, { service_name: service })

          potentials = actual.find_all do |line|
            line.match?(expected_line)
          end

          next unless potentials && !potentials.empty?
          actual_munge[service] ||= []
          actual_munge[service] += potentials.map(&:to_s)

          potentials.each do |potential|
            case @args_type
            when :all_without_args
              retval = !potential.module_arguments.join(' ').match?(@args)
              throw :stop_searching unless retval
            when :all_with_args
              retval = potential.module_arguments.join(' ').match?(@args)
              throw :stop_searching unless retval
            when :all_with_integer_arg
              retval = matching_integer_arg? potential
              throw :stop_searching unless retval
            when :any_with_integer_arg
              retval = matching_integer_arg? potential
              throw :stop_searching if retval
            when :any_with_args
              retval = potential.module_arguments.join(' ').match?(@args)
              throw :stop_searching if retval
            end
          end
        end
      end
    else
      retval = actual.include?(expected, { service_name: actual.service })
    end

    @actual = if actual_munge.empty?
                actual.to_s
              elsif actual_munge.keys.length == 1
                actual_munge.values.flatten.join("\n")
              else
                actual_munge.map do |service, lines|
                  lines.map do |line|
                    service + ' ' + line
                  end
                end.flatten.join("\n")
              end

    retval
  end

  diffable

  # TODO: make these an array of args so that we can actually chain them together
  chain :any_with_args do |args|
    @args_type = :any_with_args
    @args = args
  end

  chain :all_with_args do |args|
    @args_type = :all_with_args
    @args = args
  end

  chain :all_without_args do |args|
    @args_type = :all_without_args
    @args = args
  end

  chain :all_with_integer_arg do |key, op, value|
    @args_type = :all_with_integer_arg
    @args = { key: key, operator: op, value: value }
  end

  chain :any_with_integer_arg do |key, op, value|
    @args_type = :any_with_integer_arg
    @args = { key: key, operator: op, value: value }
  end

  description do
    res = "include #{expected}"
    case @args_type
    when :all_with_args
      res += ", all with args #{@args}"
    when :all_without_args
      res += ", all without args #{@args}"
    when :all_with_integer_arg
      res += ", all with arg #{@args[:key]} #{@args[:operator]} #{@args[:value]}"
    when :any_with_integer_arg
      res += ", any with arg #{@args[:key]} #{@args[:operator]} #{@args[:value]}"
    when :any_with_args
      res += ", any with args #{@args}"
    end
    res
  end
end

RSpec::Matchers.define :match_pam_rules do |expected|
  match do |actual|
    @expected = expected.to_s
    @actual = actual.to_s

    if @exactly && actual.respond_to?(:include_exactly?)
      actual.include_exactly?(expected)
    else
      actual.include?(expected)
    end
  end

  diffable

  chain :exactly do
    @exactly = true
  end

  description do
    res = "include #{expected}"
    res += ' exactly' unless @exactly.nil?
    res
  end
end
