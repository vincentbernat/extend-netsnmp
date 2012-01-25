/*
 * Note: this file originally auto-generated by mib2c using
 *       version : 14170 $ of $
 *
 * $Id:$
 */
#ifndef ETHTOOLSTATTABLE_H
#define ETHTOOLSTATTABLE_H

#ifdef __cplusplus
extern "C" {
#endif


/** @addtogroup misc misc: Miscellaneous routines
 *
 * @{
 */
#include <net-snmp/library/asn1.h>

/* other required module components */
    /* *INDENT-OFF*  */
config_add_mib(ETHTOOL-MIB)
config_require(ETHTOOL-MIB/ethtoolStatTable/ethtoolStatTable_interface)
config_require(ETHTOOL-MIB/ethtoolStatTable/ethtoolStatTable_data_access)
config_require(ETHTOOL-MIB/ethtoolStatTable/ethtoolStatTable_data_get)
config_require(ETHTOOL-MIB/ethtoolStatTable/ethtoolStatTable_data_set)
    /* *INDENT-ON*  */

/* OID and column number definitions for ethtoolStatTable */
#include "ethtoolStatTable_oids.h"

/* enum definions */
#include "ethtoolStatTable_enums.h"

/* *********************************************************************
 * function declarations
 */
void init_ethtoolStatTable(void);
void shutdown_ethtoolStatTable(void);

/* *********************************************************************
 * Table declarations
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
/* *********************************************************************
 * When you register your mib, you get to provide a generic
 * pointer that will be passed back to you for most of the
 * functions calls.
 *
 * TODO:100:r: Review all context structures
 */
    /*
     * TODO:101:o: |-> Review ethtoolStatTable registration context.
     */
typedef netsnmp_data_list ethtoolStatTable_registration;

/**********************************************************************/
/*
 * TODO:110:r: |-> Review ethtoolStatTable data context structure.
 * This structure is used to represent the data for ethtoolStatTable.
 */
/*
 * This structure contains storage for all the columns defined in the
 * ethtoolStatTable.
 */
typedef struct ethtoolStatTable_data_s {
    
        /*
         * ethtoolStat(2)/COUNTER64/ASN_COUNTER64/U64(U64)//l/A/w/e/r/d/h
         */
   U64   ethtoolStat;
    
} ethtoolStatTable_data;


/*
 * TODO:120:r: |-> Review ethtoolStatTable mib index.
 * This structure is used to represent the index for ethtoolStatTable.
 */
typedef struct ethtoolStatTable_mib_index_s {

        /*
         * ifIndex(1)/InterfaceIndex/ASN_INTEGER/long(long)//l/A/w/e/R/d/H
         */
   long   ifIndex;

        /*
         * ethtoolStatName(1)/ShortDisplayString/ASN_OCTET_STR/char(char)//L/a/w/e/R/d/H
         */
   char   ethtoolStatName[100];
   size_t      ethtoolStatName_len;


} ethtoolStatTable_mib_index;

    /*
     * TODO:121:r: |   |-> Review ethtoolStatTable max index length.
     * If you KNOW that your indexes will never exceed a certain
     * length, update this macro to that length.
     *
     * BE VERY CAREFUL TO TAKE INTO ACCOUNT THE MAXIMUM
     * POSSIBLE LENGHT FOR EVERY VARIABLE LENGTH INDEX!
     * Guessing 128 - col/entry(2)  - oid len(10)
*/
#define MAX_ethtoolStatTable_IDX_LEN     102


/* *********************************************************************
 * TODO:130:o: |-> Review ethtoolStatTable Row request (rowreq) context.
 * When your functions are called, you will be passed a
 * ethtoolStatTable_rowreq_ctx pointer.
 */
typedef struct ethtoolStatTable_rowreq_ctx_s {

    /** this must be first for container compare to work */
    netsnmp_index        oid_idx;
    oid                  oid_tmp[MAX_ethtoolStatTable_IDX_LEN];
    
    ethtoolStatTable_mib_index        tbl_idx;
    
    ethtoolStatTable_data              data;

    /*
     * flags per row. Currently, the first (lower) 8 bits are reserved
     * for the user. See mfd.h for other flags.
     */
    u_int                       rowreq_flags;

    /*
     * TODO:131:o: |   |-> Add useful data to ethtoolStatTable rowreq context.
     */
    
    /*
     * storage for future expansion
     */
    netsnmp_data_list             *ethtoolStatTable_data_list;

} ethtoolStatTable_rowreq_ctx;

typedef struct ethtoolStatTable_ref_rowreq_ctx_s {
    ethtoolStatTable_rowreq_ctx *rowreq_ctx;
} ethtoolStatTable_ref_rowreq_ctx;

/* *********************************************************************
 * function prototypes
 */
    int ethtoolStatTable_pre_request(ethtoolStatTable_registration * user_context);
    int ethtoolStatTable_post_request(ethtoolStatTable_registration * user_context,
        int rc);


    ethtoolStatTable_rowreq_ctx *
                  ethtoolStatTable_row_find_by_mib_index(ethtoolStatTable_mib_index *mib_idx);

extern oid ethtoolStatTable_oid[];
extern int ethtoolStatTable_oid_size;


#include "ethtoolStatTable_interface.h"
#include "ethtoolStatTable_data_access.h"
#include "ethtoolStatTable_data_get.h"
#include "ethtoolStatTable_data_set.h"

/*
 * DUMMY markers, ignore
 *
 * TODO:099:x: *************************************************************
 * TODO:199:x: *************************************************************
 * TODO:299:x: *************************************************************
 * TODO:399:x: *************************************************************
 * TODO:499:x: *************************************************************
 */

#ifdef __cplusplus
}
#endif

#endif /* ETHTOOLSTATTABLE_H */
/** @} */
