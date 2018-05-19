/*
 * This is automatically generated callbacks file
 * It contains 3 parts: Configuration callbacks, RPC callbacks and state data callbacks.
 * Do NOT alter function signatures or any structures unless you know exactly what you are doing.
 */

#include <stdlib.h>
#include <sys/inotify.h>
#include <libxml/tree.h>
#include <libnetconf_xml.h>
#include <pthread.h>

#include "../ydyos-netconf.h"
#include <arpa/inet.h>

#define NC_ydyos_SHELL_DPI        "/opt/vyatta/sbin/ydyos-shell-dpion.sh"
#define NC_ydyos_SHELL_DPIADAPTION       "/opt/vyatta/sbin/ydyos-shell-dpiAdaption.sh"
#define NC_ydyos_RPC_RETURN_REPREAT   "<result>\ndpi module works now and request will process later\n</result>"
#define NC_ydyos_RPC_RETURN_NORESOURCE   "<result>\nno more resource for request\n</result>"


#define __DPI_DEBUG__
#ifdef __DPI_DEBUG__
#define DPI_DEBUG(format, ...) printf("line %d: "format"\n", __LINE__, ##__VA_ARGS__)
#else
#define DPI_DEBUG(format, ...)
#endif

#define MAX_TRAFFIC 10
#define MAX_NICNUM 2

#define NC_NS_ydyos_DPI "urn:ydyos:params:xml:ns:yang:ydyos-dpi"

//DPI支持的协议类型
int saveProtoCnt=243;
char* saveProto[]={"Unknown","FTP_CONTROL","POP3","SMTP","IMAP","DNS","IPP","HTTP","MDNS","NTP",
"NetBIOS","NFS","SSDP","BGP","SNMP","XDMCP","SMB","Syslog","DHCP","PostgreSQL",
"MySQL","Hotmail","Direct_Download_Link","POPS","AppleJuice","DirectConnect","ntop","COAP","VMware","SMTPS",
"Filetopia","UBNTAC2","Kontiki","OpenFT","FastTrack","Gnutella","eDonkey","BitTorrent","EPP","AVI",
"Flash","OggVorbis","MPEG","QuickTime","RealMedia","WindowsMedia","MMS","Xbox","QQ","PlaceholderA",
"RTSP","IMAPS","IceCast","PPLive","PPStream","Zattoo","ShoutCast","Sopcast","Tvants","TVUplayer",
"HTTP_Download","QQLive","Thunder","Soulseek","SSL_No_Cert","IRC","Ayiya","Unencrypted_Jabber","MSN","Oscar",
"Yahoo","BattleField","GooglePlus","VRRP","Steam","HalfLife2","WorldOfWarcraft","Telnet","STUN","IPsec",
"GRE","ICMP","IGMP","EGP","SCTP","OSPF","IP_in_IP","RTP","RDP","VNC",
"PcAnywhere","SSL","SSH","Usenet","MGCP","IAX","TFTP","AFP","Stealthnet","Aimini",
"SIP","TruPhone","ICMPV6","DHCPV6","Armagetron","Crossfire","Dofus","Fiesta","Florensia","Guildwars",
"HTTP_Application_ActiveSync","Kerberos","LDAP","MapleStory","MsSQL-TDS","PPTP","Warcraft3","WorldOfKungFu","Slack","Facebook",
"Twitter","Dropbox","GMail","GoogleMaps","YouTube","Skype","Google","DCE_RPC","NetFlow","sFlow",
"HTTP_Connect","HTTP_Proxy","Citrix","NetFlix","LastFM","Waze","YouTubeUpload","ICQ","CHECKMK","AJP",
"Apple","Webex","WhatsApp","AppleiCloud","Viber","AppleiTunes","Radius","WindowsUpdate","TeamViewer","Tuenti",
"LotusNotes","SAP","GTP","UPnP","LLMNR","RemoteScan","Spotify","WebM","H323","OpenVPN",
"NOE","CiscoVPN","TeamSpeak","Tor","CiscoSkinny","RTCP","RSYNC","Oracle","Corba","UbuntuONE",
"Whois-DAS","Collectd","SOCKS","Nintendo","RTMP","FTP_DATA","Wikipedia","ZeroMQ","Amazon","eBay",
"CNN","Megaco","Redis","Pando_Media_Booster","VHUA","Telegram","Vevo","Pandora","QUIC","WhatsAppVoice",
"EAQ","Ookla","AMQP","KakaoTalk","KakaoTalk_Voice","Twitch","QuickPlay","WeChat","MPEG_TS","Snapchat",
"Sina(Weibo)","GoogleHangout","IFLIX","Github","BJNP","1kxun","iQIYI","SMPP","DNScrypt","TINC",
"Deezer","Instagram","Microsoft","Starcraft","Teredo","HotspotShield","HEP","GoogleDrive","OCS","Office365",
"Cloudflare","MS_OneDrive","MQTT","RX","AppleStore","OpenDNS","Git","DRDA","PlayStore","SOMEIP",
"FIX","Playstation","Pastebin","LinkedIn","SoundCloud","CSGO","LISP","Diameter","ApplePush","GoogleServices",
"AmazonVideo","GoogleDocs","WhatsAppFile"};

//common file LANNW
char commonlannw[30];
char commonnexthop[30];
char commonnumpoint=0;
//打开dpi检测和关闭dpi检测开关
int dpiflag=0;
char port[10];
int ret;
pthread_t dpiCheck_tid;
pthread_attr_t dpiCheck_attr;

//记录已经设置过的协议和端口
typedef struct _protolPort
{
    int  dpiAdapCnt;
    int  dpiAdaFlag;
    char dpiAdapProtol[30];
    char dpiAdapPort2[30];
    char dpiAdapLanNW[30];
    char dpiAdapNextHop2[30];
    char dpiAdapNextHop[30];
    int threadNum;
}protolPort;
//打开dpi自适应调整方案
int dpiAdpThreadCnt=0;
int dpiAdpFlag=0;
protolPort record[MAX_NICNUM][MAX_TRAFFIC];
pthread_t dpiAdaption_tid[MAX_NICNUM];
pthread_attr_t dpiAdaption_attr[MAX_NICNUM];

void initParams(int nicnum,int trafficnum)
{
    //index 参考范围为0~10
    record[nicnum][trafficnum].dpiAdaFlag=0;
    record[nicnum][trafficnum].dpiAdapCnt=0;
    memset(record[nicnum][trafficnum].dpiAdapProtol,0,sizeof(record[nicnum][trafficnum].dpiAdapProtol));
    memset(record[nicnum][trafficnum].dpiAdapPort2,0,sizeof(record[nicnum][trafficnum].dpiAdapPort2));
    memset(record[nicnum][trafficnum].dpiAdapLanNW,0,sizeof(record[nicnum][trafficnum].dpiAdapLanNW));
    memset(record[nicnum][trafficnum].dpiAdapNextHop2,0,sizeof(record[nicnum][trafficnum].dpiAdapNextHop2));
    memset(record[nicnum][trafficnum].dpiAdapNextHop,0,sizeof(record[nicnum][trafficnum].dpiAdapNextHop));
    record[nicnum][trafficnum].threadNum=0xff;
}
int getNoUseValidThreadNum(int *nicnum,int *trafficnum)
{
    int flag=0;
    int j=0;
    int i=0;
    for(i=0;i<MAX_NICNUM;i++)
    {
        flag=0;
	    for(j=0;j<MAX_TRAFFIC;j++)
	    {
	        if(strstr(record[i][j].dpiAdapPort2,"eth")==NULL)
		 	   continue;
		    else
		    {
               flag=1;
			   break;
		    }
	    }
	    if(flag==0)
	  	   *nicnum=i;
	    else
	  	   continue;
	  
	    for(j=0;j<MAX_TRAFFIC;j++)
	    {
            if(record[i][j].threadNum==0xff)
            {
                *trafficnum=j;
			    break;
		    }
	    }
   	}
    return 0xff;
}
int getValidThreadNum(int *nicnum,int *trafficnum,char* nicport)
{
    int j=0;
	int i=0;
	int flag=0;
	int tflag=0;
	for(i=0;i<MAX_NICNUM;i++)
	{
	    flag=0;
	    for(j=0;j<MAX_TRAFFIC;j++)
	    { 
            if(strcmp(record[i][j].dpiAdapPort2,nicport)==0)
            {
                *nicnum=i;
		        flag=1;
		        break;
		    }
        }
	    if(flag==1)
	  	   break;
    }
	if(flag==1)
	{
        for(j=0;j<MAX_TRAFFIC;j++)
        {
            if(record[*nicnum][j].threadNum==0xff)
            {
               *trafficnum=j;
			   break;
		    }
	    }
	}
	else if(flag==0)
	{
        for(i=0;i<MAX_NICNUM;i++)
	    {
	        tflag=0;
	        for(j=0;j<MAX_TRAFFIC;j++)
	        { 
	            if(strstr(record[i][j].dpiAdapPort2,"eth")!=NULL)
	            {
                    tflag=1;
			        break;
		        }
	        }
		    if(tflag==0)
		    {
                *nicnum=i;
		        for(j=0;j<MAX_TRAFFIC;j++)
                {
                    if(record[*nicnum][j].threadNum==0xff)
                    {
                        *trafficnum=j;
			            break;
		            }
	            }
		        break;
		    }
        }
	}
    return flag;
}
int getValidRule()
{
    int i=0;
	int j=0;
	for(i=0;i<MAX_NICNUM;i++)
	{
	    for(j=0;j<MAX_TRAFFIC;j++)
	    { 
            if(record[i][j].threadNum!=0xff)
	 	       return 1;
	    }
    }
    return 0;
}
static int finish(char* msg, int ret, struct nc_err** error) {
	if (ret != EXIT_SUCCESS && error != NULL) {
		*error = nc_err_new(NC_ERR_OP_FAILED);
		if (msg != NULL) {
			nc_err_set(*error, NC_ERR_PARAM_MSG, msg);
		}
	}

	if (msg != NULL) {
		nc_verb_error(msg);
		free(msg);
	}

	return ret;
}
static char *get_rand_string(int length)
{
	char *str = NULL;
	int i;

	srand(time(NULL));

	str = (char*)malloc(length * sizeof(char));
	for(i = 0; i < length-1 ; i++)
	{
		str[i] = rand()%('z'-'a' + 1) + 'a';
	}
	str[length-1] = '\0';
	
	return str;
}

static int exec_cmd(char *cmd, char **result, int cmd_group) {
    pid_t status;
	unsigned int file_size = 0;
	int ret = -1;
	char *cmd_tmp = NULL;
	char *file_name = NULL;
	FILE *fp = NULL;

    if (NULL == cmd) {
		asprintf(result, "%s: input cmd is NULL.", __func__);
        return -1;
    }

	file_name = get_rand_string(10);
	if (NULL == file_name) {
        asprintf(result, "create temporary file error.");
        return -1;
	}
	
    if (cmd_group == NC_ydyos_CONFIGURATION_CMD) {
        asprintf(&cmd_tmp, "sg vyattacfg -c \"%s\" > %s", cmd, file_name);
    }
    else if (cmd_group == NC_ydyos_SHOW_CMD) {
        asprintf(&cmd_tmp, "sg vyattacfg -c \'%s\' %s > %s", cmd, NC_ydyos_SHELL_SHOW_FORMAT_XML, file_name);
    }
    else {
        asprintf(&cmd_tmp, "%s > %s", cmd, file_name);
    }
    status = system(cmd_tmp);
	free(cmd_tmp);

	if (-1 == status) {
        asprintf(result, "execute system command failure when fork subprocess.");
        ret = -1;
    }
	else {
		if (WIFEXITED(status)) {
			if (0 == WEXITSTATUS(status)) {
				/* execute shell script success */
				fp = fopen(file_name, "r");
				if (NULL != fp) {
					fseek(fp, 0, SEEK_END);
					file_size = ftell(fp);
					fseek(fp, 0, SEEK_SET);

					/* for rpc */
					if (file_size > 0) {
						*result = (char *)malloc(file_size * sizeof(char));
						fread(*result, file_size, sizeof(char), fp);
						(*result)[file_size-1] = '\0';
					}
					/* for callback */
					else {
						/* in callback, when executing shell script success, file_size == 0 */
						asprintf(result, "ok");
					}
					
					fclose(fp);

					ret = 0;
				}
				else {
					asprintf(result, "%s: Open temporary file failure.", __func__);
					ret = -1;
				}
			}
			else {
				/* execute script failure, return error message */
				fp = fopen(file_name, "r");
				if (NULL != fp) {
					fseek(fp, 0, SEEK_END);
					file_size = ftell(fp);
					fseek(fp, 0, SEEK_SET);
					*result = (char *)malloc(file_size * sizeof(char));
					fread(*result, file_size, sizeof(char), fp);
					(*result)[file_size-1] = '\0';
					fclose(fp);

					ret = 1;
				}
				else {
					asprintf(result, "%s: Open temporary file failure.", __func__);
					ret = -1;
				}
			}
		}
		else {
			asprintf(result, "create subprocess error.");
			ret = -1;
		}
	}

	/* delete the temporary file */
	asprintf(&cmd_tmp, "rm -rf %s", file_name);
	system(cmd_tmp);
	free(cmd_tmp);

	/* release file_name */
	if (file_name) {
		free(file_name);
        file_name = NULL;
	}
	
	return ret;
}
static const char* get_node_content(const xmlNodePtr node)
{
	if (node == NULL || node->children == NULL || node->children->type != XML_TEXT_NODE) {
		return NULL;
	}

	return (const char*) (node->children->content);
}
//判断是否有效IP
int check_ipaddr (char *str0) 
{
    char str[100];
    strcpy(str,str0);
    str[strlen(str)-1]='\0';
    if (str == NULL || *str == '\0')
        return 1;

    struct sockaddr_in6 addr6; 
    struct sockaddr_in addr4; 

    if (1 == inet_pton (AF_INET, str, &addr4.sin_addr))
         return 1;
    else if (1 == inet_pton (AF_INET6, str, &addr6.sin6_addr))
         return 1;
    return 0;
}
int getRule(char* msg,int threadnum)
{
    int i=0;
    int tmp=0;
    for(i=0;i<MAX_TRAFFIC;i++)
    {
        if(strcmp(msg,record[threadnum][i].dpiAdapProtol)==0)
        {
            return (threadnum*MAX_TRAFFIC+i+1+100);
	    }
    }

    return 0;
}
int checkDPIProtol(char* msg, char* port,int *nicnum,int *trafficnum)
{
    int i=0;
    int j=0;
    DPI_DEBUG("%s : %d : dpiCnt=%d,protol=%s,port=%s",__FUNCTION__,__LINE__,dpiAdpThreadCnt,msg,port);
    for(i=0;i<MAX_NICNUM;i++)
    {
	    for(j=0;j<MAX_TRAFFIC;j++)
	    {
            if(strcmp(msg,record[i][j].dpiAdapProtol)==0&&strcmp(port,record[i][j].dpiAdapPort2)==0)
            {    
	            DPI_DEBUG("%s : %d protol=%s ,port=%s found",__FUNCTION__,__LINE__,msg,port);
		        *nicnum=i;
		        *trafficnum=j;
	            return j;
	        }
        }
    }
    return 0xff;
}
int ifHasSet(char* nicport)
{
    int i=0;
	int j=0;
	for(i=0;i<MAX_NICNUM;i++)
	{
	    for(j=0;j<MAX_TRAFFIC;j++)
	    {
            if(strcmp(record[i][j].dpiAdapPort2,nicport)==0)
		  	   return i;
	    }
	}
	return 0xff;
}
/* transAPI version which must be compatible with libnetconf */
int transapi_version = 6;

/* Signal to libnetconf that configuration data were modified by any callback.
 * 0 - data not modified
 * 1 - data have been modified
 */
int config_modified = 0;

/*
 * Determines the callbacks order.
 * Set this variable before compilation and DO NOT modify it in runtime.
 * TRANSAPI_CLBCKS_LEAF_TO_ROOT (default)
 * TRANSAPI_CLBCKS_ROOT_TO_LEAF
 */
const TRANSAPI_CLBCKS_ORDER_TYPE callbacks_order = TRANSAPI_CLBCKS_ORDER_DEFAULT;

/* Do not modify or set! This variable is set by libnetconf to announce edit-config's error-option
Feel free to use it to distinguish module behavior for different error-option values.
 * Possible values:
 * NC_EDIT_ERROPT_STOP - Following callback after failure are not executed, all successful callbacks executed till
                         failure point must be applied to the device.
 * NC_EDIT_ERROPT_CONT - Failed callbacks are skipped, but all callbacks needed to apply configuration changes are executed
 * NC_EDIT_ERROPT_ROLLBACK - After failure, following callbacks are not executed, but previous successful callbacks are
                         executed again with previous configuration data to roll it back.
 */
NC_EDIT_ERROPT_TYPE erropt = NC_EDIT_ERROPT_NOTSET;

/**
 * @brief Initialize plugin after loaded and before any other functions are called.

 * This function should not apply any configuration data to the controlled device. If no
 * running is returned (it stays *NULL), complete startup configuration is consequently
 * applied via module callbacks. When a running configuration is returned, libnetconf
 * then applies (via module's callbacks) only the startup configuration data that
 * differ from the returned running configuration data.

 * Please note, that copying startup data to the running is performed only after the
 * libnetconf's system-wide close - see nc_close() function documentation for more
 * information.

 * @param[out] running	Current configuration of managed device.

 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
int transapi_init(xmlDocPtr *running) {
	return EXIT_SUCCESS;
}

/**
 * @brief Free all resources allocated on plugin runtime and prepare plugin for removal.
 */
void transapi_close(void) {
	return;
}

/**
 * @brief Retrieve state data from device and return them as XML document
 *
 * @param model	Device data model. libxml2 xmlDocPtr.
 * @param running	Running datastore content. libxml2 xmlDocPtr.
 * @param[out] err  Double pointer to error structure. Fill error when some occurs.
 * @return State data as libxml2 xmlDocPtr or NULL in case of error.
 */
xmlDocPtr get_state_data(xmlDocPtr model, xmlDocPtr running, struct nc_err **err) {
	return(NULL);
}
/*
 * Mapping prefixes with namespaces.
 * Do NOT modify this structure!
 */
struct ns_pair namespace_mapping[] = {{"ydyos-dpi", "urn:ydyos:params:xml:ns:yang:ydyos-dpi"}, {NULL, NULL}};

/*
 * CONFIGURATION callbacks
 * Here follows set of callback functions run every time some change in associated part of running datastore occurs.
 * You can safely modify the bodies of all function as well as add new functions for better lucidity of code.
 */

/**
 * @brief This callback will be run when node in path /ydyos-dpi:dpi/ydyos-dpi:say-hello changes
 *
 * @param[in] data	Double pointer to void. Its passed to every callback. You can share data using it.
 * @param[in] op	Observed change in path. XMLDIFF_OP type.
 * @param[in] old_node	Old configuration node. If op == XMLDIFF_ADD, it is NULL.
 * @param[in] new_node	New configuration node. if op == XMLDIFF_REM, it is NULL.
 * @param[out] error	If callback fails, it can return libnetconf error structure with a failure description.
 *
 * @return EXIT_SUCCESS or EXIT_FAILURE
 */
/* !DO NOT ALTER FUNCTION SIGNATURE! */
int callback_ydyos_dpi_dpi_ydyos_dpi_say_hello(void **data, XMLDIFF_OP op, xmlNodePtr old_node, xmlNodePtr new_node, struct nc_err **error) {
	return EXIT_SUCCESS;
}

/*
 * Structure transapi_config_callbacks provide mapping between callback and path in configuration datastore.
 * It is used by libnetconf library to decide which callbacks will be run.
 * DO NOT alter this structure
 */
struct transapi_data_callbacks clbks =  {
	.callbacks_count = 1,
	.data = NULL,
	.callbacks = {
		{.path = "/ydyos-dpi:dpi/ydyos-dpi:say-hello", .func = callback_ydyos_dpi_dpi_ydyos_dpi_say_hello}
	}
};

/**
 * @brief Get a node from the RPC input. The first found node is returned, so if traversing lists,
 * call repeatedly with result->next as the node argument.
 *
 * @param name	Name of the node to be retrieved.
 * @param node	List of nodes that will be searched.
 * @return Pointer to the matching node or NULL
 */
xmlNodePtr get_rpc_node(const char *name, const xmlNodePtr node) {
	xmlNodePtr ret = NULL;

	for (ret = node; ret != NULL; ret = ret->next) {
		if (xmlStrEqual(BAD_CAST name, ret->name)) {
			break;
		}
	}

	return ret;
}
/////////////////////////////////////////////////////////////////
void *dpi_thread(void *arg)
{
    char cmd[150];
    char cmd_tmp[150];
    char shell_path[256] = {0};
    char *msg = NULL;
    char *shell_result = NULL;
    int index=0;
    int index2=0;

    nc_reply *reply = NULL;
    struct nc_err *err = NULL;
    char *cmd2 = NULL;
  
    while(dpiflag)
    {
        memset(shell_path,0,sizeof(shell_path));
	    memset(cmd,0,sizeof(cmd));
	    memset(cmd_tmp,0,sizeof(cmd_tmp));
	    sprintf(cmd_tmp, "bash %s ", NC_ydyos_SHELL_DPI);
	    strcpy(shell_path, cmd_tmp);
	    strcpy(cmd, cmd_tmp);
	    memset(cmd_tmp,0,sizeof(cmd_tmp));
        sprintf(cmd_tmp," start %s",port);
        strcat(cmd, cmd_tmp);
        DPI_DEBUG("cmd = %s", cmd);
	    if (exec_cmd(cmd, &shell_result, NC_LINUX_CMD) != ydyos_SHELL_SUCCESS)
	    {
	        if(shell_result!=NULL)
	        {
	            DPI_DEBUG("shell_result failed= %s",shell_result);
	            free(shell_result);
		        shell_result=NULL;	 
	        }
	    }
	    else
	    {
	        if(shell_result!=NULL)
	        {
	            DPI_DEBUG("shell_result ok= %s",shell_result);
		        free(shell_result);
		        shell_result=NULL;
	        }
	    }
    }
    if(dpiflag==0)
    {
	    //stop script
        memset(shell_path,0,sizeof(shell_path));
	    memset(cmd_tmp,0,sizeof(cmd_tmp));
	    sprintf(cmd_tmp, "bash %s ", NC_ydyos_SHELL_DPI);
	    strcpy(shell_path, cmd_tmp);
	    strcpy(cmd, cmd_tmp);
	    strcat(cmd, "  stop");
	    DPI_DEBUG("cmd = %s", cmd);
	    if (exec_cmd(cmd, &shell_result, NC_LINUX_CMD) != ydyos_SHELL_SUCCESS)
	    {
            err = nc_err_new(NC_ERR_OP_FAILED);
	        nc_err_set(err, NC_ERR_PARAM_MSG, shell_result);
	        nc_verb_error(shell_result);
	        free(shell_result);
	        return nc_reply_error(err);
	    }
	    else
	    {
	        reply = nc_reply_data_ns(shell_result, namespace_mapping[0].prefix);
	        DPI_DEBUG("--->rpc op success,line=%d",__LINE__);
	        DPI_DEBUG("shell_result = %s", shell_result);
	    }
	    free(shell_result);
    }
    return;
}
/////////////////////////////////////////////////////////////////
//提取netmask的位数以及需要过滤的netmask和nexthop的位数
static int getNetmaskNum(const char* msg)
{
    if(msg==NULL)
  	    return 0;
    const char* pos=strstr(msg,"/");
    int netmask=atoi(pos+1);
    int numpoint=0;
    switch(netmask)
    {
        case 8:
		    numpoint=1;
		    break;
	    case 16:
		    numpoint=2;
		    break;
	    case 24:
		    numpoint=3;
		    break;
	    default:
		    break;
    }
    return numpoint;
}
//将所需的参数拷贝到对应的空间
static int copyValid(const char* msg, int numpoint ,int param2,int threadnum,int trafficnum)
{
    int i=0;
    int len=0;
    if(param2==1)
    {
        const char* tmp=msg;
	    for(i=0;i<numpoint;i++)
	    {
            tmp=strstr(tmp,".");
	        tmp=tmp+1;
	    }
	    len=strlen(msg)-strlen(tmp-1);
	    strncpy(record[threadnum][trafficnum].dpiAdapLanNW,msg,len);
	    record[threadnum][trafficnum].dpiAdapLanNW[len]='\0';
	    return 1;
    }
    else if(param2==2)
    {
	    const char* tmp=msg;
	    for(i=0;i<numpoint;i++)
	    {
		    tmp=strstr(tmp,".");
		    tmp=tmp+1;
	    }
	    len=strlen(msg)-strlen(tmp-1);
	    strncpy(record[threadnum][trafficnum].dpiAdapNextHop,msg,len);
	    record[threadnum][trafficnum].dpiAdapNextHop[len]='\0';
	    return 2;
    }
}
////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////
//需要注意线程启动时间
void *dpiAdaption_thread(void *arg)
{ 
    //其他相关变量
    char cmd[2048];
    char cmd_tmp[1024];
    char shell_path[256] = {0};
    char *msg = NULL;
    char *shell_result = NULL;
    int index=0;
    //记录文件插入行数
    int filecnt=0;
    FILE * fp;
    //循环中所需变量
    char fname[50]; 
    char line[30];	
    char dest[30];
    int filesize=0;
  
    nc_reply *reply = NULL;
    struct nc_err *err = NULL;
    char *cmd2 = NULL;
    int rule=0;
    int addcnt=0;
    int i=0;
    int j=0;
    while(getValidRule())
    {
   	    if(!dpiflag)
	  	    break;
        for(i=0;i<MAX_NICNUM;i++)
        {
	        for(j=0;j<MAX_TRAFFIC;j++)
            {
                if(record[i][j].threadNum==0xff)
                {
                    if(record[i][j].dpiAdaFlag==1)
                    {
			            record[i][j].dpiAdapCnt=0;
			            DPI_DEBUG("protol exist=%s",record[i][j].dpiAdapProtol);
			            rule=getRule(record[i][j].dpiAdapProtol,i);
			            memset(shell_path,0,sizeof(shell_path));
			            memset(cmd,0,sizeof(cmd));
			            memset(cmd_tmp,0,sizeof(cmd_tmp));
			            //rm old configure
			            sprintf(cmd_tmp, "sg vyattacfg -c \"bash %s ", NC_ydyos_SHELL_DELETE);
			            strcpy(shell_path, cmd_tmp);
			            strcpy(cmd, cmd_tmp);
		
			            memset(cmd_tmp, 0, sizeof(cmd_tmp));
			            sprintf(cmd_tmp, "'policy route %s-ROUTE rule %d' ", record[i][j].dpiAdapPort2,rule);
			            //sprintf(cmd_tmp, "'firewall group address-group %s-IP' ", record[i][j].dpiAdapProtol);
			            strcat(cmd, cmd_tmp);
			            strcat(cmd,"\"");
			            DPI_DEBUG("cmd = %s", cmd);
			            if (exec_cmd(cmd, &shell_result, NC_LINUX_CMD) != ydyos_SHELL_SUCCESS)
			            {
			                if(shell_result!=NULL)
			                {
				                DPI_DEBUG("shell_result failed= %s",shell_result);
				                free(shell_result);
				                shell_result=NULL;    
			                }
			            }
			            else
			            {
				            if(shell_result!=NULL)
				            {
				                DPI_DEBUG("shell_result ok= %s",shell_result);
				                free(shell_result);
				                shell_result=NULL;
				            }
			            }
			            record[i][j].dpiAdaFlag=0;
		            }
	  	            continue;
                }
                memset(shell_path,0,sizeof(shell_path));
	            memset(cmd,0,sizeof(cmd));
	            memset(cmd_tmp,0,sizeof(cmd_tmp));
	            sprintf(cmd_tmp, "bash %s ", NC_ydyos_SHELL_DPIADAPTION);
	            strcpy(shell_path, cmd_tmp);
	            strcpy(cmd, cmd_tmp);
	            memset(cmd_tmp,0,sizeof(cmd_tmp));
                sprintf(cmd_tmp," %s %s %s %d",record[i][j].dpiAdapProtol,record[i][j].dpiAdapLanNW,record[i][j].dpiAdapNextHop,record[i][j].dpiAdapCnt);
	            DPI_DEBUG("dpiAdapProtol =%s,cmd_tmp =%s",record[i][j].dpiAdapProtol,cmd_tmp);
                strcat(cmd, cmd_tmp);
                DPI_DEBUG("cmd = %s", cmd);
	            if (exec_cmd(cmd, &shell_result, NC_LINUX_CMD) != ydyos_SHELL_SUCCESS)
	            {
	                if(shell_result!=NULL)
	                {
	                    DPI_DEBUG("shell_result failed= %s",shell_result);
	                    free(shell_result);
		                shell_result=NULL;	 
	                }
	            }
	            else
	            {
		            if(shell_result!=NULL)
		            {
		                 DPI_DEBUG("shell_result ok= %s",shell_result);
			             free(shell_result);
			             shell_result=NULL;
		            }
	            }
	            if(!dpiflag)
	  	           break;
	            //读取del部分
                memset(fname,0,sizeof(fname));
	            sprintf(fname,"/var/log/dpi/adaption/%s_del.txt",record[i][j].dpiAdapProtol);
	            fp=fopen(fname,"r");
	            rule=getRule(record[i][j].dpiAdapProtol,i);
	            if(fp==NULL)
	            {
		            DPI_DEBUG("fp = %s open failed", fname);	  
		            continue;
	            }
	            fseek(fp, 0L, SEEK_END);  
                filesize = ftell(fp); 
	            printf("filesize=%d\n",filesize);
	            fseek(fp, 0L, SEEK_SET);
	            if(filesize>7)
	            {
	                memset(shell_path,0,sizeof(shell_path));
		            memset(cmd,0,sizeof(cmd));
		            memset(cmd_tmp,0,sizeof(cmd_tmp));
		            sprintf(cmd_tmp, "sg vyattacfg -c \"bash %s ", NC_ydyos_SHELL_DELETE);
		            strcpy(shell_path, cmd_tmp);
		            strcpy(cmd, cmd_tmp);
		            filecnt=0;
		            while(fgets(line,100,fp)!=NULL)
		            {    
		                DPI_DEBUG("line=%s\n",line);
			            if(check_ipaddr(line)==0)
			            {
                            DPI_DEBUG("%s is not valid IP",line);
				            continue;
			            }
			            if(strlen(line)>7)
			            {
			                memset(cmd_tmp, 0, sizeof(cmd_tmp));
			                sprintf(cmd_tmp, "'firewall group address-group %s-IP address %s' ", 
							       record[i][j].dpiAdapProtol,line);
			                strcat(cmd, cmd_tmp);
				            filecnt++;
				            if(filecnt>=20)
				            {
                 	            strcat(cmd,"\"");
	  					        /* execute system commands */
					            DPI_DEBUG("cmd = %s", cmd);
					            if (exec_cmd(cmd, &shell_result, NC_LINUX_CMD) != ydyos_SHELL_SUCCESS)
					            {
					                if(shell_result!=NULL)
					                {
						                DPI_DEBUG("shell_result failed= %s",shell_result);
						                free(shell_result);
						                shell_result=NULL;    
					                }
					            }
					            else
					            {
						            if(shell_result!=NULL)
						            {
						                DPI_DEBUG("shell_result ok= %s",shell_result);
						                free(shell_result);
						                shell_result=NULL;
						            }
					            }
					            memset(shell_path,0,sizeof(shell_path));
				   	            memset(cmd,0,sizeof(cmd));
					            memset(cmd_tmp,0,sizeof(cmd_tmp));
					            sprintf(cmd_tmp, "sg vyattacfg -c \"bash %s ", NC_ydyos_SHELL_DELETE);
					            strcpy(shell_path, cmd_tmp);
					            strcpy(cmd, cmd_tmp);
					            filecnt=0;
				            }
			            }
		            }
			        strcat(cmd,"\"");
	  			    /* execute system commands */
			        DPI_DEBUG("cmd = %s", cmd);
		            if (exec_cmd(cmd, &shell_result, NC_LINUX_CMD) != ydyos_SHELL_SUCCESS)
		            {
			            if(shell_result!=NULL)
			            { 
			                DPI_DEBUG("shell_result failed= %s",shell_result);
			                free(shell_result);
			                shell_result=NULL;	 
			            }
		            }
		            else
		            {
			            if(shell_result!=NULL)
			            {
				            DPI_DEBUG("shell_result ok= %s",shell_result);
				            free(shell_result);
				            shell_result=NULL;
			            }
		            }
	            }
	            fclose(fp);
		
		        //读取add部分
                if(!dpiflag)
	  	           break;
	            memset(fname,0,sizeof(fname));
	            sprintf(fname,"/var/log/dpi/adaption/%s_add.txt",record[i][j].dpiAdapProtol);
	            fp=fopen(fname,"r");
	            rule=getRule(record[i][j].dpiAdapProtol,i);
	            if(fp==NULL)
	            {
		            DPI_DEBUG("fp = %s open failed", fname);	
		            continue;
	            }
	            fseek(fp, 0L, SEEK_END);  
                filesize = ftell(fp); 
	            printf("filesize=%d\n",filesize);
	            fseek(fp, 0L, SEEK_SET);
	            if(filesize>7)
	            {
	                memset(shell_path,0,sizeof(shell_path));
		            memset(cmd,0,sizeof(cmd));
		            memset(cmd_tmp,0,sizeof(cmd_tmp));
		            sprintf(cmd_tmp, "sg vyattacfg -c \"bash %s ", NC_ydyos_SHELL_SET);
		            strcpy(shell_path, cmd_tmp);
		            strcpy(cmd, cmd_tmp);
		            filecnt=0;
		            addcnt=0;
		            while(fgets(line,100,fp)!=NULL)
		            {
			            if(check_ipaddr(line)==0)
			            {
                            DPI_DEBUG("%s is not valid IP",line);
				            continue;
			            }
			            if(strlen(line)>7)
			            {
			                memset(cmd_tmp, 0, sizeof(cmd_tmp));
			                sprintf(cmd_tmp, "'firewall group address-group %s-IP address %s' ", 
							    record[i][j].dpiAdapProtol,line);
			                strcat(cmd, cmd_tmp);
				            filecnt++;
				            addcnt++;
				            if(filecnt>=20)
				            {
                 	            strcat(cmd,"\"");
	  					        /* execute system commands */
					            DPI_DEBUG("cmd = %s", cmd);
					            if (exec_cmd(cmd, &shell_result, NC_LINUX_CMD) != ydyos_SHELL_SUCCESS)
					            {
					                if(shell_result!=NULL)
					                {
						                DPI_DEBUG("shell_result failed= %s",shell_result);
						                free(shell_result);
						                shell_result=NULL;    
					                }
					            }
					            else
					            {
						            if(shell_result!=NULL)
						            {
						                DPI_DEBUG("shell_result ok= %s",shell_result);
						                free(shell_result);
						                shell_result=NULL;
						            }
					            }
					            memset(shell_path,0,sizeof(shell_path));
				   	            memset(cmd,0,sizeof(cmd));
					            memset(cmd_tmp,0,sizeof(cmd_tmp));
					            sprintf(cmd_tmp, "sg vyattacfg -c \"bash %s ", NC_ydyos_SHELL_SET);
					            strcpy(shell_path, cmd_tmp);
					            strcpy(cmd, cmd_tmp);
					            filecnt=0;
				            }
			            }
		            }
		            strcat(cmd,"\"");
	  			    /* execute system commands */
			        DPI_DEBUG("cmd = %s", cmd);
		            if (exec_cmd(cmd, &shell_result, NC_LINUX_CMD) != ydyos_SHELL_SUCCESS)
		            {
			            if(shell_result!=NULL)
			            {
			                DPI_DEBUG("shell_result failed= %s",shell_result);
			                free(shell_result);
			                shell_result=NULL;	 
			            }
		            }
		            else
		            {
			            if(shell_result!=NULL)
			            {
				            DPI_DEBUG("shell_result ok= %s",shell_result);
				            free(shell_result);
				            shell_result=NULL;
			            }
		            }
			
		            if(record[i][j].dpiAdapCnt==0&&addcnt>=1)
		            {
			            //第一次设置，移除旧的配置
			            memset(shell_path,0,sizeof(shell_path));
				        memset(cmd,0,sizeof(cmd));
				        memset(cmd_tmp,0,sizeof(cmd_tmp));
				        //rm old configure
				        sprintf(cmd_tmp, "sg vyattacfg -c \"bash %s ", NC_ydyos_SHELL_DELETE);
				        strcpy(shell_path, cmd_tmp);
				        strcpy(cmd, cmd_tmp);
				        memset(cmd_tmp, 0, sizeof(cmd_tmp));
				        sprintf(cmd_tmp, "'interfaces ethernet %s policy route %s-ROUTE' ", 
								 record[i][j].dpiAdapPort2,record[i][j].dpiAdapPort2);
				        strcat(cmd, cmd_tmp);
				        memset(cmd_tmp, 0, sizeof(cmd_tmp));
				        sprintf(cmd_tmp, "'protocols static table %d' ", rule);
				        strcat(cmd, cmd_tmp);
			  
				        memset(cmd_tmp, 0, sizeof(cmd_tmp));
				        sprintf(cmd_tmp, "'policy route %s-ROUTE rule %d' ", record[i][j].dpiAdapPort2,rule);
				        strcat(cmd, cmd_tmp);
				        memset(cmd_tmp, 0, sizeof(cmd_tmp));
				        sprintf(cmd_tmp, "'policy route %s-ROUTE' ", record[i][j].dpiAdapPort2);
				        strcat(cmd, cmd_tmp);
		
				        strcat(cmd,"\"");
				        DPI_DEBUG("cmd = %s", cmd);
				        if (exec_cmd(cmd, &shell_result, NC_LINUX_CMD) != ydyos_SHELL_SUCCESS)
				        {
				            if(shell_result!=NULL)
				            {
					            DPI_DEBUG("shell_result failed= %s",shell_result);
					            free(shell_result);
					            shell_result=NULL;    
				            }
				        }
				        else
				        {
					        if(shell_result!=NULL)
					        {
					            DPI_DEBUG("shell_result ok= %s",shell_result);
					            free(shell_result);
					            shell_result=NULL;
					        }
				        }

			            //设置相关路由
			            memset(shell_path,0,sizeof(shell_path));
			            memset(cmd,0,sizeof(cmd));
			            memset(cmd_tmp,0,sizeof(cmd_tmp));
			            sprintf(cmd_tmp, "sg vyattacfg -c \"bash %s ", NC_ydyos_SHELL_SET);
			            strcpy(shell_path, cmd_tmp);
			            strcpy(cmd, cmd_tmp);
			            memset(cmd_tmp, 0, sizeof(cmd_tmp));
			            sprintf(cmd_tmp, "'policy route %s-ROUTE rule %d destination group address-group %s-IP' ", 
							    record[i][j].dpiAdapPort2,rule,record[i][j].dpiAdapProtol);
			            strcat(cmd, cmd_tmp);
			            memset(cmd_tmp, 0, sizeof(cmd_tmp));
			            sprintf(cmd_tmp, "'policy route %s-ROUTE rule %d set table %d' ", 
								record[i][j].dpiAdapPort2,rule,rule);
			            strcat(cmd, cmd_tmp);

			            memset(cmd_tmp, 0, sizeof(cmd_tmp));
			            sprintf(cmd_tmp, "'protocols static table %d route 0.0.0.0/0 next-hop %s' ", 
							    rule,record[i][j].dpiAdapNextHop2);
			            strcat(cmd, cmd_tmp);

			            memset(cmd_tmp, 0, sizeof(cmd_tmp));
			            sprintf(cmd_tmp, "'interfaces ethernet %s policy route %s-ROUTE' ", 
							    record[i][j].dpiAdapPort2,record[i][j].dpiAdapPort2);
			            strcat(cmd, cmd_tmp);
			            strcat(cmd,"\"");
			            /* execute system commands */
			            DPI_DEBUG("cmd = %s", cmd);
			            if (exec_cmd(cmd, &shell_result, NC_LINUX_CMD) != ydyos_SHELL_SUCCESS)
			            {
				            if(shell_result!=NULL)
				            {
					            DPI_DEBUG("shell_result failed= %s",shell_result);
					            free(shell_result);
					            shell_result=NULL;	  
				            }
			            }
			            else
			            {
				            if(shell_result!=NULL)
				            {
					            DPI_DEBUG("shell_result ok= %s",shell_result);
					            free(shell_result);
					            shell_result=NULL;
				            }
			            }
		            }
		            if(addcnt>=1)
		            {
			            record[i][j].dpiAdapCnt++;
		            }
	            }
		        fclose(fp);	
            }
	        if(!dpiflag)
	  	        break;
        }
    }
    if(1)
    {  
        for(i=0;i<MAX_NICNUM;i++)
        {
	        for(j=0;j<MAX_TRAFFIC;j++)
            {
                DPI_DEBUG("nic=%d,traf=%d,pro=%s,port=%s",i,j,record[i][j].dpiAdapProtol,record[i][j].dpiAdapPort2);
                if(strstr(record[i][j].dpiAdapPort2,"eth")==NULL)
			        continue;
		        rule=getRule(record[i][j].dpiAdapProtol,i);
		        if(rule==0)
		           continue;
		
		        memset(shell_path,0,sizeof(shell_path));
	            memset(cmd,0,sizeof(cmd));
	            memset(cmd_tmp,0,sizeof(cmd_tmp));
	            //rm old configure
                sprintf(cmd_tmp, "sg vyattacfg -c \"bash %s ", NC_ydyos_SHELL_DELETE);
	            strcpy(shell_path, cmd_tmp);
	            strcpy(cmd, cmd_tmp);
	            memset(cmd_tmp, 0, sizeof(cmd_tmp));
	            sprintf(cmd_tmp, "'interfaces ethernet %s policy route %s-ROUTE' ", 
                        record[i][j].dpiAdapPort2,record[i][j].dpiAdapPort2);
	            strcat(cmd, cmd_tmp);
	            memset(cmd_tmp, 0, sizeof(cmd_tmp));
                sprintf(cmd_tmp, "'protocols static table %d' ", rule);
                strcat(cmd, cmd_tmp);
		
		        memset(cmd_tmp, 0, sizeof(cmd_tmp));
		        sprintf(cmd_tmp, "'firewall group address-group %s-IP' ", 
						record[i][j].dpiAdapProtol);
		        strcat(cmd, cmd_tmp);
		
	            strcat(cmd,"\"");
	            DPI_DEBUG("cmd = %s", cmd);
		        if (exec_cmd(cmd, &shell_result, NC_LINUX_CMD) != ydyos_SHELL_SUCCESS)
		        {
		            if(shell_result!=NULL)
		            {
			            DPI_DEBUG("shell_result failed= %s",shell_result);
			            free(shell_result);
			            shell_result=NULL;    
		            }
		        }
		        else
		        {
			        if(shell_result!=NULL)
			        {
			            DPI_DEBUG("shell_result ok= %s",shell_result);
			            free(shell_result);
			            shell_result=NULL;
			        }
		        }

		
		        memset(shell_path,0,sizeof(shell_path));
	            memset(cmd,0,sizeof(cmd));
	            memset(cmd_tmp,0,sizeof(cmd_tmp));
	            //rm old configure
                sprintf(cmd_tmp, "sg vyattacfg -c \"bash %s ", NC_ydyos_SHELL_DELETE);
	            strcpy(shell_path, cmd_tmp);
	            strcpy(cmd, cmd_tmp);
	            memset(cmd_tmp, 0, sizeof(cmd_tmp));
                sprintf(cmd_tmp, "'policy route %s-ROUTE rule %d' ", record[i][j].dpiAdapPort2,rule);
                strcat(cmd, cmd_tmp);
	            memset(cmd_tmp, 0, sizeof(cmd_tmp));
	            sprintf(cmd_tmp, "'policy route %s-ROUTE' ", record[i][j].dpiAdapPort2);
	            strcat(cmd, cmd_tmp);
	
	            strcat(cmd,"\"");
	            DPI_DEBUG("cmd = %s", cmd);
		        if (exec_cmd(cmd, &shell_result, NC_LINUX_CMD) != ydyos_SHELL_SUCCESS)
		        {
		            if(shell_result!=NULL)
		            {
			            DPI_DEBUG("shell_result failed= %s",shell_result);
			            free(shell_result);
			            shell_result=NULL;    
		            }
		        }
		        else
		        {
			        if(shell_result!=NULL)
			        {
			            DPI_DEBUG("shell_result ok= %s",shell_result);
			            free(shell_result);
			            shell_result=NULL;
			        }
		        }
		        initParams(i,j);
            }
        }
    }
    dpiAdpFlag=0;
    return;
}

////////////////////////////////////////////////////////////////
/*
 * RPC callbacks
 * Here follows set of callback functions run every time RPC specific for this device arrives.
 * You can safely modify the bodies of all function as well as add new functions for better lucidity of code.
 * Every function takes an libxml2 list of inputs as an argument.
 * If input was not set in RPC message argument is set to NULL. To retrieve each argument, preferably use get_rpc_node().
 */

nc_reply *rpc_on_dpicheck(xmlNodePtr input) {
    const char* dpiValue = NULL;
	const char* dpiPort = NULL;
	int ret;
	int i,j;
	xmlNodePtr ret2 = NULL;
    nc_reply *reply = NULL;
	struct nc_err *err = NULL;
    for (ret2 = input; ret2 != NULL; ret2 = ret2->next)
	{
        if (xmlStrcmp(ret2->name, BAD_CAST "dpicheck") == 0)
	    {
		    dpiValue = get_node_content(ret2);
		    DPI_DEBUG("dpiValue = %s", dpiValue);
  	    }
	    else if (xmlStrcmp(ret2->name, BAD_CAST "nicport") == 0)
	    {
		    dpiPort = get_node_content(ret2);
		    DPI_DEBUG("dpiPort = %s", dpiPort);
		    strcpy(port,dpiPort);
  	    }
    }
	if(dpiValue!=NULL&&(strcmp(dpiValue,"true")==0))
	{
	    if(dpiflag==1)
	    {
            return nc_reply_data_ns(NC_ydyos_RPC_RETURN_REPREAT, NC_NS_ydyos_DPI);
	    }
	    //创建线程并开启脚本检测
        dpiflag=1;
	    ret = pthread_attr_init(&dpiCheck_attr);
        if (ret != 0) 
	    {
            DPI_DEBUG("pthread_attr_init failed.");
			return nc_reply_data_ns(NC_ydyos_RPC_RETURN_FAILED, NC_NS_ydyos_DPI);

        } 

        ret = pthread_attr_setdetachstate(&dpiCheck_attr, PTHREAD_CREATE_DETACHED);
        if (ret != 0) 
	    {
            DPI_DEBUG("pthread_attr_setdetachstate failed.");
			return nc_reply_data_ns(NC_ydyos_RPC_RETURN_FAILED, NC_NS_ydyos_DPI);
        } 

        ret = pthread_create(&dpiCheck_tid, &dpiCheck_attr, dpi_thread, NULL);
        if (ret != 0) 
	    {
			return nc_reply_data_ns(NC_ydyos_RPC_RETURN_FAILED, NC_NS_ydyos_DPI);
        } 

        ret = pthread_attr_destroy(&dpiCheck_attr);
        if (ret != 0) 
	    {
			return nc_reply_data_ns(NC_ydyos_RPC_RETURN_FAILED, NC_NS_ydyos_DPI);
        } 
	    for(i=0;i<MAX_NICNUM;i++)
	    {
		    for(j=0;j<MAX_TRAFFIC;j++)
		    {
		        initParams(i,j);
		    }
	    }
		return nc_reply_data_ns(NC_ydyos_RPC_RETURN_SUCCESS, NC_NS_ydyos_DPI);
	}
	else if(dpiValue!=NULL&&(strcmp(dpiValue,"true")!=0))
	{
         //关闭线程并关闭脚本检测及相关路由策略
         dpiflag=0;
	     if(dpiAdpFlag==0)
	     {
	         for(i=0;i<MAX_NICNUM;i++)
             {
	             for(j=0;j<MAX_TRAFFIC;j++)
                 {
                     initParams(i,j);
	             }
	         }
	     }
		 return nc_reply_data_ns(NC_ydyos_RPC_RETURN_SUCCESS, NC_NS_ydyos_DPI);
	}
	else
	{
      //返回错误
	}
	return NULL;
}
nc_reply *rpc_on_adaption(xmlNodePtr input) {
    const char* dpiAdapValue = NULL;
	const char* dpiAdapProtocl = NULL;
	const char* dpiAdapPort = NULL;
	const char* dpiAdaLanNW = NULL;
	const char* dpiAdaNextHop = NULL;
	
	int ret;
	xmlNodePtr ret2 = NULL;
    nc_reply *reply = NULL;
	struct nc_err *err = NULL;
	int threadnum;
	int trafficnum;
	int setflag=0;
    for (ret2 = input; ret2 != NULL; ret2 = ret2->next)
	{
        if (xmlStrcmp(ret2->name, BAD_CAST "adaption") == 0)
	    {
		    dpiAdapValue = get_node_content(ret2);
		    DPI_DEBUG("dpiValue = %s", dpiAdapValue);
  	    }
	    else if (xmlStrcmp(ret2->name, BAD_CAST "protol") == 0)
	    {
		    dpiAdapProtocl = get_node_content(ret2);
		    DPI_DEBUG("dpiAdapProtocl = %s", dpiAdapProtocl);
  	    }
	    else if (xmlStrcmp(ret2->name, BAD_CAST "nicport") == 0)
	    {
		    dpiAdapPort = get_node_content(ret2);
		    DPI_DEBUG("dpiAdapPort = %s", dpiAdapPort);
  	    }
	    else if (xmlStrcmp(ret2->name, BAD_CAST "lannw") == 0)
	    {
		    dpiAdaLanNW = get_node_content(ret2);
		    DPI_DEBUG("dpiAdaLanNW = %s", dpiAdaLanNW);
  	    }
	    else if (xmlStrcmp(ret2->name, BAD_CAST "nexthop") == 0)
	    {
		    dpiAdaNextHop = get_node_content(ret2);
		    DPI_DEBUG("dpiAdaNextHop = %s", dpiAdaNextHop);
  	    }
    }
	if(dpiAdapValue!=NULL&&(strcmp(dpiAdapValue,"true")==0))
	{
	    if(checkDPIProtol(dpiAdapProtocl,dpiAdapPort,&threadnum,&trafficnum)!=0xff)
	    {
			return nc_reply_data_ns(NC_ydyos_RPC_RETURN_REPREAT, NC_NS_ydyos_DPI);
	    }
	    else
	    {
	        threadnum=0xff,trafficnum=0xff;
            setflag=getValidThreadNum(&threadnum,&trafficnum,dpiAdapPort);
		    if(threadnum==0xff||trafficnum==0xff)
		    {
				return nc_reply_data_ns(NC_ydyos_RPC_RETURN_NORESOURCE, NC_NS_ydyos_DPI);
		    }
		    else
		    {
                initParams(threadnum,trafficnum);
		        int numpoint=getNetmaskNum(dpiAdaLanNW);
                record[threadnum][trafficnum].dpiAdaFlag=1;
		        record[threadnum][trafficnum].dpiAdapCnt=0;
		        record[threadnum][trafficnum].threadNum=threadnum;
		        strcpy(record[threadnum][trafficnum].dpiAdapProtol,dpiAdapProtocl);
		        strcpy(record[threadnum][trafficnum].dpiAdapPort2,dpiAdapPort);
		        strcpy(record[threadnum][trafficnum].dpiAdapNextHop2,dpiAdaNextHop);
			    if(dpiAdpFlag==1)
			    {
		            copyValid(commonlannw, commonnumpoint, 1,threadnum,trafficnum);
		            copyValid(commonnexthop, commonnumpoint, 2,threadnum,trafficnum);
			    }
			    else
			    {
                    copyValid(dpiAdaLanNW, numpoint, 1,threadnum,trafficnum);
		            copyValid(dpiAdaNextHop, numpoint, 2,threadnum,trafficnum);
			    }
			    if(dpiAdpFlag==1)
			    {
					return nc_reply_data_ns(NC_ydyos_RPC_RETURN_REPREAT, NC_NS_ydyos_DPI);
			    }
			    commonnumpoint=numpoint;
			    strcpy(commonlannw,dpiAdaLanNW);
			    strcpy(commonnexthop,dpiAdaNextHop);
			    dpiAdpFlag=1;
		    }
		}
	     //创建线程并开启脚本检测
	    ret = pthread_attr_init(&dpiAdaption_tid[dpiAdpThreadCnt]);
        if (ret != 0) 
	    {
            DPI_DEBUG("pthread_attr_init failed.");
			return nc_reply_data_ns(NC_ydyos_RPC_RETURN_FAILED, NC_NS_ydyos_DPI);
        } 
	  
	    DPI_DEBUG("dpiAdpP=%s ",record[threadnum][trafficnum].dpiAdapProtol);
        ret = pthread_attr_setdetachstate(&dpiAdaption_attr[dpiAdpThreadCnt], PTHREAD_CREATE_DETACHED);
        if (ret != 0) 
	    {
            DPI_DEBUG("pthread_attr_setdetachstate failed.");
			return nc_reply_data_ns(NC_ydyos_RPC_RETURN_FAILED, NC_NS_ydyos_DPI);
        } 
	    DPI_DEBUG("dpiAdpP=%s ",record[threadnum][trafficnum].dpiAdapProtol);
        ret = pthread_create(&dpiAdaption_tid[dpiAdpThreadCnt], &dpiAdaption_attr[dpiAdpThreadCnt], dpiAdaption_thread,NULL);
        if (ret != 0) 
	    {
            DPI_DEBUG("pthread_create failed.");
			return nc_reply_data_ns(NC_ydyos_RPC_RETURN_FAILED, NC_NS_ydyos_DPI);
        } 
	    DPI_DEBUG("dpiAdpP=%s ",record[threadnum][trafficnum].dpiAdapProtol);

        ret = pthread_attr_destroy(&dpiAdaption_attr[dpiAdpThreadCnt]);
        if (ret != 0) 
	    {
            DPI_DEBUG("pthread_attr_destroy failed.");
			return nc_reply_data_ns(NC_ydyos_RPC_RETURN_FAILED, NC_NS_ydyos_DPI);
        } 
		return nc_reply_data_ns(NC_ydyos_RPC_RETURN_SUCCESS, NC_NS_ydyos_DPI);
	}
	else if(dpiAdapValue!=NULL&&(strcmp(dpiAdapValue,"true")!=0))
	{
        //关闭线程并关闭脚本检测及相关路由策略
        threadnum=0xff,trafficnum=0xff;
        checkDPIProtol(dpiAdapProtocl,dpiAdapPort,&threadnum,&trafficnum);
	    if(threadnum!=0xff&&trafficnum!=0xff)
	    {
	        record[threadnum][trafficnum].threadNum=0xff;
	    }
		return nc_reply_data_ns(NC_ydyos_RPC_RETURN_SUCCESS, NC_NS_ydyos_DPI);
	}
	else
	{
      //返回错误
	}
	return NULL;
}
nc_reply *rpc_set_protocol(xmlNodePtr input) {
	//TODO
	return NULL;
}
/*
 * Structure transapi_rpc_callbacks provides mapping between callbacks and RPC messages.
 * It is used by libnetconf library to decide which callbacks will be run when RPC arrives.
 * DO NOT alter this structure
 */
struct transapi_rpc_callbacks rpc_clbks = {
	.callbacks_count = 3,
	.callbacks = {
		{.name="on-dpicheck", .func=rpc_on_dpicheck},
		{.name="on-adaption", .func=rpc_on_adaption},
		{.name="set-protocol", .func=rpc_set_protocol}
	}
};

/*
 * Structure transapi_file_callbacks provides mapping between specific files
 * (e.g. configuration file in /etc/) and the callback function executed when
 * the file is modified.
 * The structure is empty by default. Add items, as in example, as you need.
 *
 * Example:
 * int example_callback(const char *filepath, xmlDocPtr *edit_config, int *exec) {
 *     // do the job with changed file content
 *     // if needed, set edit_config parameter to the edit-config data to be applied
 *     // if needed, set exec to 1 to perform consequent transapi callbacks
 *     return 0;
 * }
 *
 * struct transapi_file_callbacks file_clbks = {
 *     .callbacks_count = 1,
 *     .callbacks = {
 *         {.path = "/etc/my_cfg_file", .func = example_callback}
 *     }
 * }
 */
struct transapi_file_callbacks file_clbks = {
	.callbacks_count = 0,
	.callbacks = {{NULL}}
};

