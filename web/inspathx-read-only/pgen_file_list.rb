#!/usr/bin/env ruby
#
# Takes source path and a file which contains a list of paths to directories
# cat list
#   1024cms_v2.1
#   b2e1.2
#   wordpress1.4
#
# e.g.
# ruby pgen_file_list.rb /sources/ list

require 'find'
require 'erb'

rootpath = ARGV[0] #dir
sourcepath = ARGV[1] #list

filter = /\.(php|asp|aspx|jsp|jspx)$/i

sf = File.new(sourcepath,"r")

pathname = ''

while fline = sf.gets
    fu = ''
    if fline.length > 1 and fline !~ /^#/ and  fline !~ /^list/ 
        fu = fline.to_s
        
        fu.gsub!("\n","")
        fu.gsub!("\r\n","")
        pathname = fu
        
        system("ruby inspathx.rb -d \"#{pathroot}#{pathname}\" -g \"paths/#{pathname}\" -c \"#{pathname}\"")
        
    end
end
sf.close

