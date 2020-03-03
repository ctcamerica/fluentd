require 'net/http'
require 'uri'
require 'json'
require 'digest'
require 'open3'
require 'fileutils'
require 'net/ssh'
require 'net/scp'
require 'zlib'

class MyNode
	### Initialize with default configuration
	def initialize(ip_or_hostname)
		@name = ip_or_hostname
		@config_path = '/etc/td-agent/'
		@config_file = 'td-agent.conf'
		@td_agent_log_path = '/var/log/td-agent/'
		@td_agent_log_file = 'td-agent.log'
		@os_log_path = '/var/log/'
		@os_log_file = 'messages'
		@sysctl_path = '/etc/'
		@sysctl_file = 'sysctl.conf'
		@user = 'root'  # may be replaced
		@work_dir = '/tmp/work/fluent_log_test/'+ @name
		@prod_dir = @work_dir + '/prod'
		@copy_dir = @work_dir + '/copy'
		FileUtils.mkdir_p(@prod_dir+@config_path)
		FileUtils.mkdir_p(@prod_dir+@td_agent_log_path)
		FileUtils.mkdir_p(@prod_dir+@os_log_path)
		FileUtils.mkdir_p(@prod_dir+@sysctl_path)
		FileUtils.mkdir_p(@copy_dir+@config_path)
		FileUtils.mkdir_p(@copy_dir+@td_agent_log_path)
		FileUtils.mkdir_p(@copy_dir+@os_log_path)
		FileUtils.mkdir_p(@copy_dir+@sysctl_path)
	end
	def collect_td_agent_conf()
		Net::SSH.start(@name, @user) do | session |
			session.scp.download!(@config_path+@config_file, @copy_dir+@config_path)
		end
		return @copy_dir+@config_path+@config_file
	end
        def collect_td_agent_log()
                Net::SSH.start(@name, @user) do | session |
             		session.scp.download!(@td_agent_log_path, @copy_dir+@os_log_path, :recursive => true, :verbose => true)
			files = session.exec!("ls -d #{@copy_dir+@td_agent_log_path}/* | grep #{@td_agent_log_file}")
			return files.split()
		end
        end
        def collect_sysctl_conf()
                Net::SSH.start(@name, @user) do | session |
                        session.scp.download!(@sysctl_path+@sysctl_file, @copy_dir+@sysctl_path)
                        session.scp.download!(@sysctl_path+@sysctl_file, @prod_dir+@sysctl_path)
                end
		return @copy_dir+@sysctl_path+@sysctl_file
        end
        def collect_os_log()
                Net::SSH.start(@name, @user) do | session |
                        session.scp.download!(@os_log_path+@os_log_file, @copy_dir+@os_log_path)
                        session.scp.download!(@os_log_path+@os_log_file, @prod_dir+@os_log_path)
                end
		return @copy_dir+@os_log_path+@os_log_file
        end
	def mask_td_agent_conf(input_file)
        	f = File.open(@prod_dir+@config_path+@config_file+'.mask', 'w')
        	File.readlines(input_file).each do |line|
			line_masked = mask_td_agent_conf_inspector(line)                	
                	f.print(line_masked+"\n")
        	end
        	f.close
	end
        def mask_td_agent_log(input_file)
		filename = input_file.split("/")[-1]
                f = File.open(@prod_dir+@td_agent_log_path+filename+'.mask', 'w')
		File.readlines(input_file).each do |line|
                      	line_masked = mask_td_agent_log_inspector(line)
                     	f.print(line_masked+"\n")
                end
                f.close
        end
	def mask_td_agent_log_gz(input_file)
                filename = input_file.split("/")[-1]
                f = File.open(@prod_dir+@td_agent_log_path+filename+'.mask', 'w')
		gunzip_file = @copy_dir+@td_agent_log_path+'tmpfile'
		system("gunzip --keep -c #{input_file} > #{gunzip_file}")
		File.readlines(gunzip_file).each do |line|
			line_masked = mask_td_agent_log_inspector(line)
                        f.print(line_masked+"\n")
                end   		
                f.close
        end
	def mask_td_agent_conf_inspector(line)
		i = 0
		contents=[]
		loop do
			contents[i] = line.split()[i]
			if is_ipv4?(contents[i])
				contents[i] = 'ipv4_md5_'+Digest::MD5.hexdigest(contents[i])
				contents[i] << ">" if contents[0].include? "<"
			elsif is_fqdn?(contents[i])
				contents[i] = 'fqdn_md5_'+Digest::MD5.hexdigest(contents[i])
				contents[i] << ">" if contents[0].include? "<"
			end
			i+=1
			break if i >= line.split().length
		end
		line_mask = contents.join(' ')
		return line_mask
	end
	def mask_td_agent_log_inspector(line)
		i = 0
		contents=[]
		loop do
			contents[i] = line.split()[i]
			if contents[i].include? "host="
				l = contents[i].split("=") ## Mask host=<ipaddress or hostname>
				l[1] = 'ipv4_md5_'+Digest::MD5.hexdigest(l[1].gsub(/\"/){ '' }) if is_ipv4?(l[1].gsub(/\"/){ '' })
				l[1] = 'fqdn_md5_'+Digest::MD5.hexdigest(l[1].gsub(/\"/){ '' }) if is_fqdn?(l[1].gsub(/\"/){ '' })
				contents[i] = l.join("=")
	                elsif contents[i].include? "bind=" ## Mask bind=<ipaddress or hostname>
                                l = contents[i].split("=")
                                l[1] = 'ipv4_md5_'+Digest::MD5.hexdigest(l[1].gsub(/\"/){ '' }) if is_ipv4?(l[1].gsub(/\"/){ '' })
                                l[1] = 'fqdn_md5_'+Digest::MD5.hexdigest(l[1].gsub(/\"/){ '' }) if is_fqdn?(l[1].gsub(/\"/){ '' })
                                contents[i] = l.join("=")
			elsif contents[i].include? ":" ## Mask <ipaddress or hostname>:<port>
				l = contents[i].split(":")
				l[0] = 'ipv4_md5_'+Digest::MD5.hexdigest(l[0]) if is_ipv4?(l[0])
				l[0] = 'fqdn_md5_'+Digest::MD5.hexdigest(l[0].gsub(/\'/){ '' }) if is_fqdn?(l[0].gsub(/\'/){ '' })
				contents[i] = l.join(":")
			elsif is_fqdn?(contents[i].gsub(/\"/){ '' }) ## Mask <ipaddress>
				contents[i] = 'fqdn_md5_'+Digest::MD5.hexdigest(contents[i].gsub(/\"/){ '' })
			elsif is_ipv4?(contents[i].gsub(/\"/){ '' }) ## Mask <hostname>
				contents[i] = 'ipv4_md5_'+Digest::MD5.hexdigest(contents[i].gsub(/\"/){ '' })
			end
			i+=1
			break if i >= line.split().length
		end
		line_masked = contents.join(' ')
		return line_masked
	end
	def is_ipv4?(str)
        	!!(str =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/)
	end
	def is_fqdn?(str)
        	!!(str =~ /^\b([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}\b/)
	end
	def collect_ulimit()
		f = File.open(@prod_dir+'/ulimit_info.output', 'w')
        	Net::SSH.start(@name, @user) do | session |
			ret =  session.exec!("ulimit -n").gsub(/\n/){ '' }
			f.print(ret)
			return ret
		end
		f.close
	end
	def collect_ntp()
		f = File.open(@prod_dir+'/ntp_info.output', 'w')
                Net::SSH.start(@name, @user) do | session |
                        date = session.exec!("date")
			f.print(date)
			chrony = session.exec!("chronyc sources")
			f.print(chrony)
			return date
                end
		f.close
        end
end

####
# Main
####

node1 = MyNode.new('centos8101.demo.com')
td_agent_log = node1.collect_td_agent_log()
td_agent_conf = node1.collect_td_agent_conf()
sysctl_conf =  node1.collect_sysctl_conf()
os_log = node1.collect_os_log()

node1.mask_td_agent_conf(td_agent_conf)
td_agent_log.each do | file |
	filename = file.split("/")[-1]
        if filename.include?(".gz")
		node1.mask_td_agent_log_gz(file)
	elsif
		p filename 
		node1.mask_td_agent_log(file)
	end
end
node1.collect_ulimit()
node1.collect_ntp() 

#node2 = MyNode.new('centos8102.demo.com')
#node2.collect_td_agent_log()
#node2.collect_td_agent_conf()
#node2.collect_sysctl_conf()
#node2.collect_os_log()
#node2.mask_td_agent_conf()
#node2.mask_td_agent_log()



