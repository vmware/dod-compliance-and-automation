require 'kubernetes'

class KubeProcessBaseResource < Inspec.resource(1)
  name 'kube_process'
  desc 'Custom resource to validate any kubernetes process configs'

  def initialize(process = nil)
    @process = process
  end

  def exist?
    inspec.processes(@process).exist?
  end

  def method_missing(name)
    read_params[name.to_s] || nil
  end

  def params
    @params ||= read_params
  end

  def to_s
    "Process arguments for #{@process}"
  end

  private

  ##
  # Reads process for flags for the specified process and/or component-flag.
  # K3S Process flags are of the following formats
  # 1) --<component-flag>='<param>=<values>'
  # 2) --<component-flag> <param>=<values>
  # 3) --<param>=<values>
  # 4) --<param> <values>
  # Returns: Hash of parsed param and values and key and value

  def read_params
    return @params if defined?(@params)
    return {} unless exist?

    if @process.include?('k3s')
      commands = inspec.service(@process).params['ExecStart']
    else
      commands = inspec.processes(@process).commands.join
    end

    # Format string for regex
    commands = "#{commands.gsub(/'/, ' ')} "
    flags = commands.scan(/--#{@component_flag}[=|\s]?([^:]*?)[=|\s](.*?)\s/)

    @params = {}
    flags.each do |flag|
      k, v = flag
      if @params[k]
        @params[k] << v
      else
        @params[k] = [v]
      end
    end

    @params
  end
end
