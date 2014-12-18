#!/usr/bin/env ruby
#
# Takes a directory path and cms name
# dir source
#     1024cms_v2.1
#     b2e1.2
#     wordpress1.4
#
# e.g
# ruby pgen_dir_path.rb /sources/ foo-bar-cms-1.0

path = ARGV[0]
name = ARGV[1]
        
system("ruby inspathx.rb -d \"#{path}\" -g \"paths/#{name}\" -c \"#{name}\"")


