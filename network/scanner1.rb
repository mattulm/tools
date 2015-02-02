#!/usr/bin/ruby

require 'socket'

def scanner(h, p)
	sock = Socket.new(:INET, :STREAM)
	raw = Socket.sockaddr_in(p, h)
	puts "#{p} open." if sock.connect(raw)

rescue (Errno::ECONNREFUSED)
	rescue(Errno::ETIMEDOUT)
end

def main(h, s_port, e_port)
	until s_port == e_port do
		scanner(h, s_port)
		s_port += 1
	end
end

main ARGV[0], ARGV[1].to_i, ARGV[2].to_i

