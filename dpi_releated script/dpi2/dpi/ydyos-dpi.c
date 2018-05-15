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

#define NC_ydyOS_SHELL_DPI        "/opt/vyatta/sbin/ydyos-shell-dpion.sh"
#define NC_ydyOS_SHELL_DPIADAPTION       "/opt/vyatta/sbin/ydyos-shell-dpiAdaption.sh"

#define __DPI_DEBUG__
#ifdef __DPI_DEBUG__
#define DPI_DEBUG(format, ...) printf("line %d: "format"\n", __LINE__, ##__VA_ARGS__)
#else
#define DPI_DEBUG(format, ...)
#endif
//记录已经设置过的协议和端口
typedef struct _protolPort{
  char protol[30];
  char port[10];
}protolPort;
int dpiCnt=0;
protolPort record[20];
//打开dpi检测和关闭dpi检测开关
int dpiflag=0;
char port[10];
int ret;
pthread_t dpiCheck_tid;
pthread_attr_t dpiCheck_attr;

//打开dpi自适应调整方案
int dpiAdapCnt=0;
int dpiAdaFlag=0;
char dpiAdapProtol[30]={0};
char dpiAdapPort2[30]={0};
char dpiAdapLanNW[30]={0};
char dpiAdapNextHop2[30]={0};
char dpiAdapNextHop[30]={0};

pthread_t dpiAdaption_tid;
pthread_attr_t dpiAdaption_attr;

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

static int exec_cmd(char *cmd, char **result) {
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
	
	asprintf(&cmd_tmp, "%s > %s", cmd, file_name);
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

static int getRule(char* msg)
{
  if(strcmp(msg,"QQ")==0)
  	return 100;
  else
  	return 200;
}
static int checkDPIProtol(char* msg, char* port)
{
  int i=0;
  int flag=0;
  DPI_DEBUG("%s : %d : dpiCnt=%d,protol=%s,port=%s",__FUNCTION__,__LINE__,dpiCnt,msg,port);
  for(i=0;i<dpiCnt;i++)
  {
    
    if(strcmp(msg,record[i].protol)==0&&strcmp(port,record[i].port)==0)
    {
      
	  DPI_DEBUG("%s : %d protol=%s ,port=%s found",__FUNCTION__,__LINE__,msg,port);
      flag=1;
	  break;
	}
  }
  if(flag==1)
  {
    return 1;
  }
  else
  {
    strcpy(record[dpiCnt].protol,msg);
	strcpy(record[dpiCnt].port,port);
	
	DPI_DEBUG("%s : %d record %d [%s ,%s ]",__FUNCTION__,__LINE__,dpiCnt,msg,port);
	dpiCnt++;
	return 0;
  }
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

  nc_reply *reply = NULL;
  struct nc_err *err = NULL;
  char *cmd2 = NULL;
  
  while(dpiflag)
  {
      memset(shell_path,0,sizeof(shell_path));
	  memset(cmd,0,sizeof(cmd));
	  memset(cmd_tmp,0,sizeof(cmd_tmp));
	  sprintf(cmd_tmp, "bash %s ", NC_ydyOS_SHELL_DPI);
	  strcpy(shell_path, cmd_tmp);
	  strcpy(cmd, cmd_tmp);
	  memset(cmd_tmp,0,sizeof(cmd_tmp));
      sprintf(cmd_tmp," start %s",port);
      strcat(cmd, cmd_tmp);
      DPI_DEBUG("cmd = %s", cmd);
	  if (exec_cmd(cmd, &shell_result) != ydyOS_SHELL_SUCCESS)
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
	  sprintf(cmd_tmp, "bash %s ", NC_ydyOS_SHELL_DPI);
	  strcpy(shell_path, cmd_tmp);
	  strcpy(cmd, cmd_tmp);
	  strcat(cmd, "  stop");
	  DPI_DEBUG("cmd = %s", cmd);
	  if (exec_cmd(cmd, &shell_result) != ydyOS_SHELL_SUCCESS)
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
	  for(index=0;index<dpiCnt;index++)
	  {
	    //delete policy
	    int rule2=getRule(record[index].protol);
	    //rm old configure
	    memset(shell_path,0,sizeof(shell_path));
	    memset(cmd,0,sizeof(cmd));
	    memset(cmd_tmp,0,sizeof(cmd_tmp));
	    sprintf(cmd_tmp, "sg vyattacfg -c \"bash %s ", NC_ydyOS_SHELL_DELETE);
	    strcpy(shell_path, cmd_tmp);
	    strcpy(cmd, cmd_tmp);
	    memset(cmd_tmp, 0, sizeof(cmd_tmp));
	    sprintf(cmd_tmp, "'interfaces ethernet %s policy route %s-ROUTE' ", 
							  record[index].port,record[index].protol);
	    strcat(cmd, cmd_tmp);
	    memset(cmd_tmp, 0, sizeof(cmd_tmp));
	    sprintf(cmd_tmp, "'protocols static table %d' ", rule2);
	    strcat(cmd, cmd_tmp);
		strcat(cmd,"\"");
	    DPI_DEBUG("cmd = %s", cmd);
		
		if (exec_cmd(cmd, &shell_result) != ydyOS_SHELL_SUCCESS)
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
	    memset(cmd_tmp,0,sizeof(cmd_tmp));
	    memset(cmd,0,sizeof(cmd));
	    sprintf(cmd_tmp, "sg vyattacfg -c \"bash %s ", NC_ydyOS_SHELL_DELETE);
	    strcpy(shell_path, cmd_tmp);
	    strcpy(cmd, cmd_tmp);
			
	    memset(cmd_tmp, 0, sizeof(cmd_tmp));
	    sprintf(cmd_tmp, "'policy route %s-ROUTE rule %d' ", record[index].protol,rule2);
	    strcat(cmd, cmd_tmp);
	    memset(cmd_tmp, 0, sizeof(cmd_tmp));
	    sprintf(cmd_tmp, "'policy route %s-ROUTE' ", record[index].protol);
	    strcat(cmd, cmd_tmp);
		strcat(cmd,"\"");
	    DPI_DEBUG("cmd = %s", cmd);
		if (exec_cmd(cmd, &shell_result) != ydyOS_SHELL_SUCCESS)
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
	    memset(cmd_tmp,0,sizeof(cmd_tmp));
	    memset(cmd,0,sizeof(cmd));
	    sprintf(cmd_tmp, "sg vyattacfg -c \"bash %s ", NC_ydyOS_SHELL_DELETE);
	    strcpy(shell_path, cmd_tmp);
	    strcpy(cmd, cmd_tmp);
	  
	    memset(cmd_tmp, 0, sizeof(cmd_tmp));
	    sprintf(cmd_tmp, "'firewall group address-group %s-IP' ", record[index].protol);
	    strcat(cmd, cmd_tmp);
		strcat(cmd,"\"");
	    DPI_DEBUG("cmd = %s", cmd);
		if (exec_cmd(cmd, &shell_result) != ydyOS_SHELL_SUCCESS)
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
static int copyValid(const char* msg, int numpoint ,int param2)
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
	 strncpy(dpiAdapLanNW,msg,len);
	 dpiAdapLanNW[len]='\0';
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
	  strncpy(dpiAdapNextHop,msg,len);
	  dpiAdapNextHop[len]='\0';
	  return 2;
  }
}
////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////
//需要注意线程启动时间
void *dpiAdaption_thread(void *arg)
{
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
  DPI_DEBUG("dpiAdaFlag=%d",dpiAdaFlag);
  while(dpiAdaFlag)
  {
      memset(shell_path,0,sizeof(shell_path));
	  memset(cmd,0,sizeof(cmd));
	  memset(cmd_tmp,0,sizeof(cmd_tmp));
	  sprintf(cmd_tmp, "bash %s ", NC_ydyOS_SHELL_DPIADAPTION);
	  strcpy(shell_path, cmd_tmp);
	  strcpy(cmd, cmd_tmp);
	  memset(cmd_tmp,0,sizeof(cmd_tmp));
      sprintf(cmd_tmp," %s %s %s %d",dpiAdapProtol,dpiAdapLanNW,dpiAdapNextHop,dpiAdapCnt);
	  DPI_DEBUG("dpiAdapProtol =%s,cmd_tmp =%s",dpiAdapProtol,cmd_tmp);
      strcat(cmd, cmd_tmp);
      DPI_DEBUG("cmd = %s", cmd);
	  if (exec_cmd(cmd, &shell_result) != ydyOS_SHELL_SUCCESS)
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
	  
	  //读取del部分
      memset(fname,0,sizeof(fname));
	  sprintf(fname,"/var/log/dpi/adaption/%s_del.txt",dpiAdapProtol);
	  fp=fopen(fname,"r");
	  rule=getRule(dpiAdapProtol);
	  if(fp==NULL)
	  {
		  DPI_DEBUG("fp = %s open failed", fname);	   
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
		  sprintf(cmd_tmp, "sg vyattacfg -c \"bash %s ", NC_ydyOS_SHELL_DELETE);
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
							dpiAdapProtol,line);
			    strcat(cmd, cmd_tmp);
				filecnt++;
				if(filecnt>=20)
				{
                 	strcat(cmd,"\"");
	  					/* execute system commands */
					DPI_DEBUG("cmd = %s", cmd);
					if (exec_cmd(cmd, &shell_result) != ydyOS_SHELL_SUCCESS)
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
					sprintf(cmd_tmp, "sg vyattacfg -c \"bash %s ", NC_ydyOS_SHELL_DELETE);
					strcpy(shell_path, cmd_tmp);
					strcpy(cmd, cmd_tmp);
					filecnt=0;
				}
			  }
		   }
			strcat(cmd,"\"");
	  			/* execute system commands */
			DPI_DEBUG("cmd = %s", cmd);
		  if (exec_cmd(cmd, &shell_result) != ydyOS_SHELL_SUCCESS)
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

	   memset(fname,0,sizeof(fname));
	   sprintf(fname,"/var/log/dpi/adaption/%s_add.txt",dpiAdapProtol);
	   fp=fopen(fname,"r");
	   rule=getRule(dpiAdapProtol);
	   if(fp==NULL)
	   {
		  DPI_DEBUG("fp = %s open failed", fname);	   
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
		  sprintf(cmd_tmp, "sg vyattacfg -c \"bash %s ", NC_ydyOS_SHELL_SET);
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
							dpiAdapProtol,line);
			    strcat(cmd, cmd_tmp);
				filecnt++;
				addcnt++;
				if(filecnt>=20)
				{
                 	strcat(cmd,"\"");
	  					/* execute system commands */
					DPI_DEBUG("cmd = %s", cmd);
					if (exec_cmd(cmd, &shell_result) != ydyOS_SHELL_SUCCESS)
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
					sprintf(cmd_tmp, "sg vyattacfg -c \"bash %s ", NC_ydyOS_SHELL_SET);
					strcpy(shell_path, cmd_tmp);
					strcpy(cmd, cmd_tmp);
					filecnt=0;
				}
			  }
		  }
		   strcat(cmd,"\"");
	  			/* execute system commands */
			DPI_DEBUG("cmd = %s", cmd);
		  if (exec_cmd(cmd, &shell_result) != ydyOS_SHELL_SUCCESS)
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
			
		  if(dpiAdapCnt==0&&addcnt>=1)
		  {
			    //第一次设置，移除旧的配置
			    memset(shell_path,0,sizeof(shell_path));
				memset(cmd,0,sizeof(cmd));
				memset(cmd_tmp,0,sizeof(cmd_tmp));
				//rm old configure
				sprintf(cmd_tmp, "sg vyattacfg -c \"bash %s ", NC_ydyOS_SHELL_DELETE);
				strcpy(shell_path, cmd_tmp);
				strcpy(cmd, cmd_tmp);
				memset(cmd_tmp, 0, sizeof(cmd_tmp));
				sprintf(cmd_tmp, "'interfaces ethernet %s policy route %s-ROUTE' ", 
								dpiAdapPort2,dpiAdapProtol);
				strcat(cmd, cmd_tmp);
				memset(cmd_tmp, 0, sizeof(cmd_tmp));
				sprintf(cmd_tmp, "'protocols static table %d' ", rule);
				strcat(cmd, cmd_tmp);
			  
				memset(cmd_tmp, 0, sizeof(cmd_tmp));
				sprintf(cmd_tmp, "'policy route %s-ROUTE rule %d' ", dpiAdapProtol,rule);
				strcat(cmd, cmd_tmp);
				memset(cmd_tmp, 0, sizeof(cmd_tmp));
				sprintf(cmd_tmp, "'policy route %s-ROUTE' ", dpiAdapProtol);
				strcat(cmd, cmd_tmp);
		
				strcat(cmd,"\"");
				DPI_DEBUG("cmd = %s", cmd);
				if (exec_cmd(cmd, &shell_result) != ydyOS_SHELL_SUCCESS)
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
			   sprintf(cmd_tmp, "sg vyattacfg -c \"bash %s ", NC_ydyOS_SHELL_SET);
			   strcpy(shell_path, cmd_tmp);
			   strcpy(cmd, cmd_tmp);
			   memset(cmd_tmp, 0, sizeof(cmd_tmp));
			   sprintf(cmd_tmp, "'policy route %s-ROUTE rule %d destination group address-group %s-IP' ", 
							dpiAdapProtol,rule,dpiAdapProtol);
			   strcat(cmd, cmd_tmp);
			   memset(cmd_tmp, 0, sizeof(cmd_tmp));
			   sprintf(cmd_tmp, "'policy route %s-ROUTE rule %d set table %d' ", 
								dpiAdapProtol,rule,rule);
			   strcat(cmd, cmd_tmp);

			   memset(cmd_tmp, 0, sizeof(cmd_tmp));
			   sprintf(cmd_tmp, "'protocols static table %d route 0.0.0.0/0 next-hop %s' ", 
							rule,dpiAdapNextHop2);
			   strcat(cmd, cmd_tmp);

			   memset(cmd_tmp, 0, sizeof(cmd_tmp));
			   sprintf(cmd_tmp, "'interfaces ethernet %s policy route %s-ROUTE' ", 
							dpiAdapPort2,dpiAdapProtol);
			   strcat(cmd, cmd_tmp);
			   strcat(cmd,"\"");
			   /* execute system commands */
			   DPI_DEBUG("cmd = %s", cmd);
			   if (exec_cmd(cmd, &shell_result) != ydyOS_SHELL_SUCCESS)
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
			dpiAdapCnt++;
		}
	   }
		fclose(fp);	
  }
  if(dpiAdaFlag==0)
  {
        dpiAdapCnt=0;
	    DPI_DEBUG("protol exist=%s",dpiAdapProtol);
	    rule=getRule(dpiAdapProtol);
		memset(shell_path,0,sizeof(shell_path));
	    memset(cmd,0,sizeof(cmd));
	    memset(cmd_tmp,0,sizeof(cmd_tmp));
	    //rm old configure
        sprintf(cmd_tmp, "sg vyattacfg -c \"bash %s ", NC_ydyOS_SHELL_DELETE);
	    strcpy(shell_path, cmd_tmp);
	    strcpy(cmd, cmd_tmp);
	    memset(cmd_tmp, 0, sizeof(cmd_tmp));
	    sprintf(cmd_tmp, "'interfaces ethernet %s policy route %s-ROUTE' ", 
                        dpiAdapPort2,dpiAdapProtol);
	    strcat(cmd, cmd_tmp);
	    memset(cmd_tmp, 0, sizeof(cmd_tmp));
        sprintf(cmd_tmp, "'protocols static table %d' ", rule);
        strcat(cmd, cmd_tmp);
	    strcat(cmd,"\"");
	    DPI_DEBUG("cmd = %s", cmd);
	    if (exec_cmd(cmd, &shell_result) != ydyOS_SHELL_SUCCESS)
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
	    /* free memory */
	    free(shell_result);	
		
		memset(shell_path,0,sizeof(shell_path));
	    memset(cmd,0,sizeof(cmd));
	    memset(cmd_tmp,0,sizeof(cmd_tmp));
	    //rm old configure
        sprintf(cmd_tmp, "sg vyattacfg -c \"bash %s ", NC_ydyOS_SHELL_DELETE);
	    strcpy(shell_path, cmd_tmp);
	    strcpy(cmd, cmd_tmp);
	    memset(cmd_tmp, 0, sizeof(cmd_tmp));
        sprintf(cmd_tmp, "'policy route %s-ROUTE rule %d' ", dpiAdapProtol,rule);
        strcat(cmd, cmd_tmp);
	    memset(cmd_tmp, 0, sizeof(cmd_tmp));
	    sprintf(cmd_tmp, "'policy route %s-ROUTE' ", dpiAdapProtol);
	    strcat(cmd, cmd_tmp);
		
	    memset(cmd_tmp, 0, sizeof(cmd_tmp));
	    sprintf(cmd_tmp, "'firewall group address-group %s-IP' ", dpiAdapProtol);
	    strcat(cmd, cmd_tmp);
	    strcat(cmd,"\"");
	    DPI_DEBUG("cmd = %s", cmd);
	    if (exec_cmd(cmd, &shell_result) != ydyOS_SHELL_SUCCESS)
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
	  /* free memory */
	   free(shell_result);
  }
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
	  //创建线程并开启脚本检测
      dpiflag=1;
	  ret = pthread_attr_init(&dpiCheck_attr);
      if (ret != 0) 
	  {
        DPI_DEBUG("pthread_attr_init failed.");
        err = nc_err_new(NC_ERR_OP_FAILED);
        nc_err_set(err, NC_ERR_PARAM_MSG, "pthread_attr_init failed.");
        nc_verb_error("pthread_attr_init failed.");
						
        return nc_reply_error(err);
      } 

      ret = pthread_attr_setdetachstate(&dpiCheck_attr, PTHREAD_CREATE_DETACHED);
      if (ret != 0) 
	  {
        DPI_DEBUG("pthread_attr_setdetachstate failed.");
        err = nc_err_new(NC_ERR_OP_FAILED);
        nc_err_set(err, NC_ERR_PARAM_MSG, "pthread_attr_setdetachstate failed.");
        nc_verb_error("pthread_attr_setdetachstate failed.");
						
        return nc_reply_error(err);
      } 

      ret = pthread_create(&dpiCheck_tid, &dpiCheck_attr, dpi_thread, NULL);
      if (ret != 0) 
	  {
        DPI_DEBUG("pthread_create failed.");
        err = nc_err_new(NC_ERR_OP_FAILED);
        nc_err_set(err, NC_ERR_PARAM_MSG, "pthread_create failed.");
        nc_verb_error("pthread_create failed.");
						
        return nc_reply_error(err);
      } 

      ret = pthread_attr_destroy(&dpiCheck_attr);
      if (ret != 0) 
	  {
        DPI_DEBUG("pthread_attr_destroy failed.");
        err = nc_err_new(NC_ERR_OP_FAILED);
        nc_err_set(err, NC_ERR_PARAM_MSG, "pthread_attr_destroy failed.");
        nc_verb_error("pthread_attr_destroy failed.");
						
        return nc_reply_error(err);
      } 
      reply = nc_reply_data_ns("open dpi ok", namespace_mapping[0].prefix);
      return reply;
	}
	else if(dpiValue!=NULL&&(strcmp(dpiValue,"true")!=0))
	{
      //关闭线程并关闭脚本检测及相关路由策略
      dpiflag=0;
	  reply = nc_reply_data_ns("close dpi ok", namespace_mapping[0].prefix);
      return reply;
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
		strcpy(dpiAdapProtol,dpiAdapProtocl);
		DPI_DEBUG("restore pro=%s ",dpiAdapProtol);
  	  }
	  else if (xmlStrcmp(ret2->name, BAD_CAST "nicport") == 0)
	  {
		dpiAdapPort = get_node_content(ret2);
		DPI_DEBUG("dpiAdapPort = %s", dpiAdapPort);
		strcpy(dpiAdapPort2,dpiAdapPort);
		DPI_DEBUG("restore pro=%s ",dpiAdapPort);
  	  }
	  else if (xmlStrcmp(ret2->name, BAD_CAST "lannw") == 0)
	  {
		dpiAdaLanNW = get_node_content(ret2);
		DPI_DEBUG("dpiAdaLanNW = %s", dpiAdaLanNW);
		int numpoint=getNetmaskNum(dpiAdaLanNW);
		copyValid(dpiAdaLanNW, numpoint, 1);
  	  }
	  else if (xmlStrcmp(ret2->name, BAD_CAST "nexthop") == 0)
	  {
		dpiAdaNextHop = get_node_content(ret2);
		DPI_DEBUG("dpiAdaNextHop = %s", dpiAdaNextHop);
		int numpoint=getNetmaskNum(dpiAdaLanNW);
		strcpy(dpiAdapNextHop2,dpiAdaNextHop);
		copyValid(dpiAdaLanNW, numpoint, 2);
  	  }
    }
	if(dpiAdapValue!=NULL&&(strcmp(dpiAdapValue,"true")==0))
	{
	  DPI_DEBUG("dpiAdpP=%s ",dpiAdapProtol);
	  if(dpiAdapProtol==1)
	  {
          reply = nc_reply_data_ns("Has Set ok Before", namespace_mapping[0].prefix);
          return reply;
	  }
	  //创建线程并开启脚本检测
      dpiAdaFlag=1;
	  ret = pthread_attr_init(&dpiAdaption_tid);
      if (ret != 0) 
	  {
        DPI_DEBUG("pthread_attr_init failed.");
        err = nc_err_new(NC_ERR_OP_FAILED);
        nc_err_set(err, NC_ERR_PARAM_MSG, "pthread_attr_init failed.");
        nc_verb_error("pthread_attr_init failed.");
						
        return nc_reply_error(err);
      } 
	  
	  DPI_DEBUG("dpiAdpP=%s ",dpiAdapProtol);
      ret = pthread_attr_setdetachstate(&dpiAdaption_attr, PTHREAD_CREATE_DETACHED);
      if (ret != 0) 
	  {
        DPI_DEBUG("pthread_attr_setdetachstate failed.");
        err = nc_err_new(NC_ERR_OP_FAILED);
        nc_err_set(err, NC_ERR_PARAM_MSG, "pthread_attr_setdetachstate failed.");
        nc_verb_error("pthread_attr_setdetachstate failed.");
						
        return nc_reply_error(err);
      } 
	  DPI_DEBUG("dpiAdpP=%s ",dpiAdapProtol);
      ret = pthread_create(&dpiAdaption_tid, &dpiAdaption_attr, dpiAdaption_thread, NULL);
      if (ret != 0) 
	  {
        DPI_DEBUG("pthread_create failed.");
        err = nc_err_new(NC_ERR_OP_FAILED);
        nc_err_set(err, NC_ERR_PARAM_MSG, "pthread_create failed.");
        nc_verb_error("pthread_create failed.");
						
        return nc_reply_error(err);
      } 
	  DPI_DEBUG("dpiAdpP=%s ",dpiAdapProtol);

      ret = pthread_attr_destroy(&dpiAdaption_attr);
      if (ret != 0) 
	  {
        DPI_DEBUG("pthread_attr_destroy failed.");
        err = nc_err_new(NC_ERR_OP_FAILED);
        nc_err_set(err, NC_ERR_PARAM_MSG, "pthread_attr_destroy failed.");
        nc_verb_error("pthread_attr_destroy failed.");
						
        return nc_reply_error(err);
      } 
      reply = nc_reply_data_ns("open dpi-pbr ok", namespace_mapping[0].prefix);
      return reply;
	}
	else if(dpiAdapValue!=NULL&&(strcmp(dpiAdapValue,"true")!=0))
	{
      //关闭线程并关闭脚本检测及相关路由策略
      dpiAdaFlag=0;
	  dpiAdapCnt=0;
	  reply = nc_reply_data_ns("close dpi-pbr ok", namespace_mapping[0].prefix);
      return reply;
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

