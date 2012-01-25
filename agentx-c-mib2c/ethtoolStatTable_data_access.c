/*
 * Note: this file originally auto-generated by mib2c using
 *       version : 14170 $ of $ 
 *
 * $Id:$
 */
/* standard Net-SNMP includes */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <linux/sockios.h>
#include <linux/ethtool.h>

/* include our parent header */
#include "ethtoolStatTable.h"


#include "ethtoolStatTable_data_access.h"

/** @ingroup interface
 * @addtogroup data_access data_access: Routines to access data
 *
 * These routines are used to locate the data used to satisfy
 * requests.
 * 
 * @{
 */
/**********************************************************************
 **********************************************************************
 ***
 *** Table ethtoolStatTable
 ***
 **********************************************************************
 **********************************************************************/
/*
 * ETHTOOL-MIB::ethtoolStatTable is subid 1 of ethtool.
 * Its status is Current.
 * OID: .1.3.6.1.4.1.39178.100.1.1, length: 10
*/

/**
 * initialization for ethtoolStatTable data access
 *
 * This function is called during startup to allow you to
 * allocate any resources you need for the data table.
 *
 * @param ethtoolStatTable_reg
 *        Pointer to ethtoolStatTable_registration
 *
 * @retval MFD_SUCCESS : success.
 * @retval MFD_ERROR   : unrecoverable error.
 */
int
ethtoolStatTable_init_data(ethtoolStatTable_registration * ethtoolStatTable_reg)
{
    DEBUGMSGTL(("verbose:ethtoolStatTable:ethtoolStatTable_init_data","called\n"));

    /*
     * TODO:303:o: Initialize ethtoolStatTable data.
     */

    return MFD_SUCCESS;
} /* ethtoolStatTable_init_data */

/**
 * container overview
 *
 */

/**
 * container initialization
 *
 * @param container_ptr_ptr A pointer to a container pointer. If you
 *        create a custom container, use this parameter to return it
 *        to the MFD helper. If set to NULL, the MFD helper will
 *        allocate a container for you.
 * @param  cache A pointer to a cache structure. You can set the timeout
 *         and other cache flags using this pointer.
 *
 *  This function is called at startup to allow you to customize certain
 *  aspects of the access method. For the most part, it is for advanced
 *  users. The default code should suffice for most cases. If no custom
 *  container is allocated, the MFD code will create one for your.
 *
 *  This is also the place to set up cache behavior. The default, to
 *  simply set the cache timeout, will work well with the default
 *  container. If you are using a custom container, you may want to
 *  look at the cache helper documentation to see if there are any
 *  flags you want to set.
 *
 * @remark
 *  This would also be a good place to do any initialization needed
 *  for you data source. For example, opening a connection to another
 *  process that will supply the data, opening a database, etc.
 */
void
ethtoolStatTable_container_init(netsnmp_container **container_ptr_ptr,
                             netsnmp_cache *cache)
{
    DEBUGMSGTL(("verbose:ethtoolStatTable:ethtoolStatTable_container_init","called\n"));
    
    if (NULL == container_ptr_ptr) {
        snmp_log(LOG_ERR,"bad container param to ethtoolStatTable_container_init\n");
        return;
    }

    /*
     * For advanced users, you can use a custom container. If you
     * do not create one, one will be created for you.
     */
    *container_ptr_ptr = NULL;

    if (NULL == cache) {
        snmp_log(LOG_ERR,"bad cache param to ethtoolStatTable_container_init\n");
        return;
    }

    /*
     * TODO:345:A: Set up ethtoolStatTable cache properties.
     *
     * Also for advanced users, you can set parameters for the
     * cache. Do not change the magic pointer, as it is used
     * by the MFD helper. To completely disable caching, set
     * cache->enabled to 0.
     */
    cache->timeout = ETHTOOLSTATTABLE_CACHE_TIMEOUT; /* seconds */
} /* ethtoolStatTable_container_init */

/**
 * container shutdown
 *
 * @param container_ptr A pointer to the container.
 *
 *  This function is called at shutdown to allow you to customize certain
 *  aspects of the access method. For the most part, it is for advanced
 *  users. The default code should suffice for most cases.
 *
 *  This function is called before ethtoolStatTable_container_free().
 *
 * @remark
 *  This would also be a good place to do any cleanup needed
 *  for you data source. For example, closing a connection to another
 *  process that supplied the data, closing a database, etc.
 */
void
ethtoolStatTable_container_shutdown(netsnmp_container *container_ptr)
{
    DEBUGMSGTL(("verbose:ethtoolStatTable:ethtoolStatTable_container_shutdown","called\n"));
    
    if (NULL == container_ptr) {
        snmp_log(LOG_ERR,"bad params to ethtoolStatTable_container_shutdown\n");
        return;
    }

} /* ethtoolStatTable_container_shutdown */

/**
 * load initial data
 *
 * TODO:350:M: Implement ethtoolStatTable data load
 * This function will also be called by the cache helper to load
 * the container again (after the container free function has been
 * called to free the previous contents).
 *
 * @param container container to which items should be inserted
 *
 * @retval MFD_SUCCESS              : success.
 * @retval MFD_RESOURCE_UNAVAILABLE : Can't access data source
 * @retval MFD_ERROR                : other error.
 *
 *  This function is called to load the index(es) (and data, optionally)
 *  for the every row in the data set.
 *
 * @remark
 *  While loading the data, the only important thing is the indexes.
 *  If access to your data is cheap/fast (e.g. you have a pointer to a
 *  structure in memory), it would make sense to update the data here.
 *  If, however, the accessing the data invovles more work (e.g. parsing
 *  some other existing data, or peforming calculations to derive the data),
 *  then you can limit yourself to setting the indexes and saving any
 *  information you will need later. Then use the saved information in
 *  ethtoolStatTable_row_prep() for populating data.
 *
 * @note
 *  If you need consistency between rows (like you want statistics
 *  for each row to be from the same time frame), you should set all
 *  data here.
 *
 */
int
ethtoolStatTable_container_load(netsnmp_container *container)
{
    ethtoolStatTable_rowreq_ctx *rowreq_ctx;
    size_t                 count = 0;

    /*
     * temporary storage for index values
     */
        /*
         * ifIndex(1)/InterfaceIndex/ASN_INTEGER/long(long)//l/A/w/e/R/d/H
         */
   long   ifIndex;
        /*
         * ethtoolStatName(1)/ShortDisplayString/ASN_OCTET_STR/char(char)//L/a/w/e/R/d/H
         */
   char   ethtoolStatName[100];
   size_t      ethtoolStatName_len;

    
    DEBUGMSGTL(("verbose:ethtoolStatTable:ethtoolStatTable_container_load","called\n"));

    int skfd;
    struct ifaddrs *ifap;
    struct ifaddrs *ifa;

    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        return MFD_RESOURCE_UNAVAILABLE;
    if (getifaddrs(&ifap) != 0) {
        close(skfd);
        return MFD_RESOURCE_UNAVAILABLE;
    }

    /*
     * TODO:351:M: |-> Load/update data in the ethtoolStatTable container.
     * loop over your ethtoolStatTable data, allocate a rowreq context,
     * set the index(es) [and data, optionally] and insert into
     * the container.
     */
    for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
	struct ethtool_drvinfo drvinfo;
	struct ethtool_gstrings *strings;
	struct ethtool_stats *stats;
	struct ifreq ifr;
	unsigned int n_stats, sz_str, sz_stats, i;

	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, ifa->ifa_name);

	drvinfo.cmd = ETHTOOL_GDRVINFO;
	ifr.ifr_data = (caddr_t) &drvinfo;
        if (ioctl(skfd, SIOCETHTOOL, &ifr) != 0)
            continue;
        n_stats = drvinfo.n_stats;
        if (n_stats < 1)
            continue;
	sz_str = n_stats * ETH_GSTRING_LEN;
	sz_stats = n_stats * sizeof(uint64_t);
	strings = calloc(1, sz_str + sizeof(struct ethtool_gstrings));
        if (!strings) {
            snmp_log(LOG_ERR,"unable to allocate memory for strings\n");
            continue;
        }
	stats = calloc(1, sz_stats + sizeof(struct ethtool_stats));
        if (!stats) {
            snmp_log(LOG_ERR,"unable to allocate memory for stats\n");
            free(strings);
            continue;
        }

	strings->cmd = ETHTOOL_GSTRINGS;
	strings->string_set = ETH_SS_STATS;
	strings->len = n_stats;
	ifr.ifr_data = (caddr_t) strings;
        if (ioctl(skfd, SIOCETHTOOL, &ifr) != 0) {
            snmp_log(LOG_ERR,"%s: error on ETHTOOL GSTRINGS ioctl: %m\n", ifa->ifa_name);
            free(strings); free(stats);
            continue;
        }

	stats->cmd = ETHTOOL_GSTATS;
	stats->n_stats = n_stats;
	ifr.ifr_data = (caddr_t) stats;
        if (ioctl(skfd, SIOCETHTOOL, &ifr) != 0) {
            snmp_log(LOG_ERR,"%s: error on ETHTOOL GSTATS ioctl: %m\n", ifa->ifa_name);
            free(strings); free(stats);
            continue;
        }

        ifIndex = if_nametoindex(ifa->ifa_name);

	for (i = 0; i < n_stats; i++) {
            strncpy(ethtoolStatName,
                    (char *)&strings->data[i * ETH_GSTRING_LEN],
                    ETH_GSTRING_LEN);
            ethtoolStatName[sizeof(ethtoolStatName) - 1] = '\0';
            ethtoolStatName_len = strlen(ethtoolStatName);

            /*
             * TODO:352:M: |   |-> set indexes in new ethtoolStatTable rowreq context.
             */
            rowreq_ctx = ethtoolStatTable_allocate_rowreq_ctx();
            if (NULL == rowreq_ctx) {
                snmp_log(LOG_ERR, "memory allocation failed\n");
                free(strings); free(stats);
                freeifaddrs(ifap); close(skfd);
                return MFD_RESOURCE_UNAVAILABLE;
            }
            if(MFD_SUCCESS != ethtoolStatTable_indexes_set(rowreq_ctx
                                                           , ifIndex
                                                           , ethtoolStatName, ethtoolStatName_len
                                                           )) {
                snmp_log(LOG_ERR,"error setting index while loading "
                         "ethtoolStatTable data.\n");
                ethtoolStatTable_release_rowreq_ctx(rowreq_ctx);
                continue;
            }
            
            /*
             * TODO:352:r: |   |-> populate ethtoolStatTable data context.
             * Populate data context here. (optionally, delay until row prep)
             */
            /*
             * TRANSIENT or semi-TRANSIENT data:
             * copy data or save any info needed to do it in row_prep.
             */
            /*
             * setup/save data for ethtoolStat
             * ethtoolStat(2)/COUNTER64/ASN_COUNTER64/U64(U64)//l/A/w/e/r/d/h
             */
            /** no mapping */
            rowreq_ctx->data.ethtoolStat.high = stats->data[i] >> 32;
            rowreq_ctx->data.ethtoolStat.low = (uint32_t)stats->data[i];
            
            
            /*
             * insert into table container
             */
            CONTAINER_INSERT(container, rowreq_ctx);
            ++count;

        }

        free(strings);
        free(stats);
    }

    freeifaddrs(ifap);
    close(skfd);

    DEBUGMSGT(("verbose:ethtoolStatTable:ethtoolStatTable_container_load",
               "inserted %d records\n", count));

    return MFD_SUCCESS;
} /* ethtoolStatTable_container_load */

/**
 * container clean up
 *
 * @param container container with all current items
 *
 *  This optional callback is called prior to all
 *  item's being removed from the container. If you
 *  need to do any processing before that, do it here.
 *
 * @note
 *  The MFD helper will take care of releasing all the row contexts.
 *
 */
void
ethtoolStatTable_container_free(netsnmp_container *container)
{
    DEBUGMSGTL(("verbose:ethtoolStatTable:ethtoolStatTable_container_free","called\n"));

    /*
     * TODO:380:M: Free ethtoolStatTable container data.
     */
} /* ethtoolStatTable_container_free */

/**
 * prepare row for processing.
 *
 *  When the agent has located the row for a request, this function is
 *  called to prepare the row for processing. If you fully populated
 *  the data context during the index setup phase, you may not need to
 *  do anything.
 *
 * @param rowreq_ctx pointer to a context.
 *
 * @retval MFD_SUCCESS     : success.
 * @retval MFD_ERROR       : other error.
 */
int
ethtoolStatTable_row_prep( ethtoolStatTable_rowreq_ctx *rowreq_ctx)
{
    DEBUGMSGTL(("verbose:ethtoolStatTable:ethtoolStatTable_row_prep","called\n"));

    netsnmp_assert(NULL != rowreq_ctx);

    /*
     * TODO:390:o: Prepare row for request.
     * If populating row data was delayed, this is the place to
     * fill in the row for this request.
     */

    return MFD_SUCCESS;
} /* ethtoolStatTable_row_prep */

/** @} */
