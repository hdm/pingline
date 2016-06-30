#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'bundler/setup'
require 'socket'
require 'ipaddr'

require 'packetfu'
require 'network_interface'

def get_root
  if RUBY_PLATFORM.index("linux") && Process.euid != 0
    this_sudo = `which rvmsudo`.index("rvmsudo") ? "rvmsudo" : "sudo"
    this_ruby = File.readlink("/proc/self/exe")
    args = [this_sudo, this_ruby, __FILE__, *ARGV]
    exec(*args)
  end
end

def get_address
  udp = UDPSocket.new
  udp.setsockopt(Socket::SOL_SOCKET, Socket::SO_BROADCAST, true)
  udp.connect(@targets.first, 53)
  family, address = Socket.unpack_sockaddr_in(udp.getsockname)
  udp.close
  address
end

def get_interface
  default_address = get_address
  NetworkInterface.interfaces.each do |intf|
    next if intf == "lo"
    addr = NetworkInterface.addresses(intf)
    next unless addr[2] && addr[17]
    if addr[2].first['addr'].to_s == default_address.to_s
      return {
        'mac'  => addr[17].first['addr'],
        'name' => intf
      }.merge(addr[2].first)
    end
  end
  nil
end

def process_input_address(arg)
  begin
    IPAddr.new(arg).to_range.each {|addr| @targets << addr.to_s }
  rescue ::Interrupt
    raise $!
  rescue IPAddr::InvalidAddressError
    print_error("Invalid IP address or range: #{arg}")
    return
  end
end

def process_input(args)
  if args.length == 0 or args.index("-h") or args.index("--help")
    usage
  end

  args.each do |arg|
    File.exists?(arg) ?
      File.readlines(arg).each {|line| process_input_address(line.strip) } :
      process_input_address(arg)
  end

  @targets.uniq!

  if @targets.length == 0
    print_error("No valid targets supplied")
    exit(1)
  end
  print_status("Loaded #{@targets.length} targets...")

  prepare_state
end

def start_processing
  Thread.new do
    begin
      processing_loop
    rescue ::Interrupt
      raise $!
    rescue ::Exception => e
      print_error("Processing Error: #{e.class} #{e} #{e.backtrace}")
    end
  end
end

def processing_loop
  loop do
  @cap.stream.each_packet do |rpkt|
    packet = PacketFu::IPPacket.parse(rpkt.data)
    next unless (
      packet.is_icmp?      &&
      packet.icmp_code == 0
      [8,0].include?(packet.icmp_type) &&
      ( @state[packet.ip_daddr] || @state[packet.ip_saddr] )
    )

    pseq = packet.payload.unpack("N").first
    next unless pseq

    if packet.ip_saddr == @int['addr']
      next if @state[packet.ip_daddr][:sent][pseq]
      rtime = rpkt.time.to_f + (rpkt.microsec / 1_000_000.0)
      @state[packet.ip_daddr][:sent][pseq] = rtime
    else
      next if @state[packet.ip_saddr][:recv][pseq]
      rtime = rpkt.time.to_f + (rpkt.microsec / 1_000_000.0)
      @state[packet.ip_saddr][:recv][pseq] = rtime
    end
  end
  end
end

def start_sending
  sending_loop
end

def sending_loop
  loop do
    transmit_start = Time.now.to_f
    packet_count = 0

    @targets.each do |target|
      send_probe(target)
      packet_count += 1
      if packet_count % 100 == 0
        sleep(0.20)
      end
    end

    # Ensure we send no faster than once a second
    transmit_time = Time.now.to_f - transmit_start
    if transmit_time < 1.0
      sleep(1.0 - transmit_time)
    end

    display_stats

    @seq += 1
  end
end

def send_probe(target)
  dest = Socket.pack_sockaddr_in(0, target)
  pkt  = PacketFu::ICMPPacket.new
  pkt.ip_saddr  = @int['addr']
  pkt.ip_daddr  = target
  pkt.ip_ttl    = 255
  pkt.icmp_type = 8
  pkt.icmp_code = 0
  pkt.payload   = [ @seq ].pack("N")
  pkt.recalc

  # Grab the generated IP packet
  # TODO: BSD/OSX require bit flipping in the IP header to host order (!)
  raw = pkt.headers[1].to_s

  # @state[target][:sent][@seq] = Time.now.to_f
  @sock_raw.send(raw, 0, dest)
end

def prepare_state
  @targets.each do |t|
    @state[t] = { sent: {}, recv: {} }
  end
end

def display_stats
  return unless @seq > 1

  $stdout.write "\x1b\x5b\x33\x3b\x4a\x1b\x5b\x48\x1b\x5b\x32\x4a"
  $stdout.flush

  # TODO: Trim data older than X?
  tseq   = @seq - 1
  twin   = 100
  tmin   = [tseq - twin, 0].max

  row = [ "ADDRESS    ", 'RTT', 'AVG', 'LOW', 'HIGH', "%LOSS", "LOST"]
  $stdout.puts row.join("\t")
  $stdout.flush

  @targets.sort{|a,b| Gem::Version.new(a) <=> Gem::Version.new(b) }.each do |t|

    lost = thi = 0
    tlo = nil
    rtt_cur = rtt_cnt = rec_cnt = last_rtt = 0


    tmin.upto(tseq) do |rseq|
      rec_cnt += 1

      next if @state[t][:sent][rseq].nil?

      if @state[t][:recv][rseq].nil?
        last_rtt = nil
        lost += 1
        next
      end
      rtt = ((@state[t][:recv][rseq] - @state[t][:sent][rseq]) * 1_000_000.0 ).to_i / 1000.0
      rtt_cur += rtt
      rtt_cnt += 1
      thi = rtt if rtt > thi
      tlo = rtt if (tlo.nil? or rtt < tlo)
      last_rtt = rtt
    end

    lost_pct = ((lost / rec_cnt.to_f) * 100).to_i

    # Skip dead hosts
    next if rtt_cnt == 0

    row = [ t, last_rtt.nil? ? '---' : last_rtt.to_i, (rtt_cur / rtt_cnt).to_i, tlo.to_i, thi.to_i, "%#{lost_pct}", "#{lost}/#{rec_cnt}"]
    $stdout.puts row.join("\t")
    $stdout.flush
  end

  if @seq % 10 == 0
    $stdout.puts "\n\nSaving state..."
    data = Marshal.dump(@state)
    File.open("state.dmp", "w") do |fd|
      fd.write(data)
    end
  end

end

def configure_sockets
  unless @sock_raw
    @sock_raw = Socket.open(Socket::PF_INET, Socket::SOCK_RAW, Socket::IPPROTO_ICMP)
    @sock_raw.setsockopt(Socket::IPPROTO_IP, Socket::IP_HDRINCL, 1)
    @sock_raw.setsockopt(Socket::SOL_SOCKET, Socket::SO_BROADCAST, true)
    @sock_raw.setsockopt(Socket::SOL_SOCKET, Socket::SO_SNDBUF, 1024*1024)
  end

  unless @cap
    @cap = PacketFu::Capture.new(
      :iface   => @int['name'],
      :start   => true,
      :filter  => "icmp and host #{@int['addr']}",
      :snaplen => 65535,
      :promisc => false
    )
  end
end

def print_status(msg)
  $stdout.puts "[*] #{msg}"
end

def print_error(msg)
  $stderr.puts "[-] #{msg}"
end

def usage
  print_error "Usage: #{$0} [/path/to/file | address | cidr]"
  exit(1)
end

#
# Main
#


@targets = []
@state   = {}
@seq     = 0

get_root
process_input(ARGV)

@int = get_interface
unless @int
  print_error("Could not determine the default interface")
  exit(1)
end

configure_sockets

processing_t = start_processing

start_sending
