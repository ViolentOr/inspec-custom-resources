# encoding: utf-8
# copyright: 2017, ViolentOr
# author: ViolentOr


class FileAudit < Inspec.resource(1)
  name 'file_audit'
  desc 'Use the InSpec resource to determine Windows File Audit params'


  def initialize(path)
    @path = path
    if !inspec.file(@path).exist?
      skip_resource "Can't find file \"#{@path}\""
      return @params = {}
    end
    @rules_array = inspec.command("(get-acl #{@path} -audit).getauditrules($true,$true, [System.Security.Principal.SecurityIdentifier] )").stdout.split("\r\n\r\n")
  end

  def amount
    puts "start amount\n"
    puts @rules_array.length
    return 0 if @rules_array.length == 0
    return @rules_array.length - 1
  end

  def to_s
    return '' if @rules_array.nil?
    return '' if @rules_array.empty?
    st = "---\n"
    options = {assignment_regex: /^\s*([^:]+?)\s*:\s*(.+?)\s*$/}
    @rules_array.each do |rule_str|
      rule = inspec.parse_config(rule_str, options)
      next if rule.params.empty?
      st += rule.params['IdentityReference'].nil? ? '' : rule.params['IdentityReference']
      st += ":\n"
      st += "  FileSystemRights: "
      st += rule.params['FileSystemRights'].nil? ? '' : rule.params['FileSystemRights']
      st += "\n"
      st += "  AuditFlags: "
      st += rule.params['AuditFlags'].nil? ? '' : rule.params['AuditFlags']
      st += "\n"
      #For registry TODO: Redo this crap
      st += "  RegistryRights: "
      st += rule.params['RegistryRights'].nil? ? '' : rule.params['RegistryRights']
      st += "\n"
      st += "  InheritanceFlags: "
      st += rule.params['InheritanceFlags'].nil? ? '' : rule.params['InheritanceFlags']
      st += "\n"
      st += "  PropagationFlags: "
      st += rule.params['PropagationFlags'].nil? ? '' : rule.params['PropagationFlags']
      st += "\n"
    end
    return st
  end
end
