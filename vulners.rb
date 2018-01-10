# encoding: utf-8
# copyright: 2018, ViolentOr
# author: ViolentOr

require 'faraday'
require 'json'

# Base settings

class VulnersApi < Inspec.resource(1)
  name 'vulners'

  def initialize(opts = {})
    @vulners_url = '/api/v3/audit/audit/'
    #TODO: Make it a param
    @proxy = 'confidential'
    @vulnerable_packages = Array.new
    @vulnerabilities = Array.new
    getVulns(getPackages)
  end

  def vulnerable?
    return true unless @vulnerabilities.size.eql?(0)
    return false
  end

  def vulnerabilities_amount
    @vulnerabilities.size
  end

  def vulnerable_pakages_amount
    @vulnerable_packages.size
  end

  def vulnerabilities
    @vulnerabilities
  end

  def vulnerable_packages
    @vulnerable_packages
  end

  private

  def getPackages
    uname = inspec.command("uname -r").stdout.to_s
    list = inspec.command("rpm -qa | grep -v '^kernel-'").stdout + inspec.command("rpm -qa |grep '^kernel.*#{uname}'").stdout
    return list.split()
  end

  def getVulns(packageList)
    conn = Faraday.new(:url => 'https://vulners.com', ssl: {verify: false})
    conn.proxy @proxy unless @proxy.nil?
    conn.headers['User-Agent'] = "inspec resource Vulners"
    
    response = conn.post do |req|
      req.url @vulners_url
      req.headers['User-Agent'] = "inspec resource Vulners"
      req.headers['Content-Type'] = 'application/json'
      req.body = '{ "os": "redhat", "package":' + packageList.to_s + ',
      "version": "7"}'
    end

    skip_resource "Vulners answered #{response.status}" unless response.status.eql?(200)
    response_json = JSON.parse(response.body)
    @vulnerable_packages = Array.new
    response_json['data']['vulnerabilities'].size.times do |i|
      @vulnerable_packages += Array(response_json['data']['reasons'][i]['providedPackage'])
    end
    @vulnerabilities = JSON.parse(response.body)['data']['vulnerabilities']
  end
end
