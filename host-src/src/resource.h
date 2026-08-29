#ifndef RESOURCE_H
#define RESOURCE_H

#define IDD_MAIN          100
#define IDI_APP           101

#define IDC_IP            1001
#define IDC_START         1002
#define IDC_STOP          1003
#define IDC_STATUS        1004
#define IDC_SITES         1005
#define IDC_BLOCK_FW      1006
#define IDC_BLOCK_GAME    1007
#define IDC_GUIDE         1008
#define IDC_FW_OPEN       1009
#define IDC_FW_OFF        1010
#define IDC_LOG           1011
#define IDC_IPLABEL       1012
#define IDC_GUIDELABEL    1013
#define IDC_TITLE         1014
#define IDC_AUTOSCROLL    1015
#define IDC_DONATE        1016
#define IDC_CUSTOM        1017
#define IDC_CUSTOMLABEL   1018
#define IDC_CUSTOM_CLEAR  1019

/* Donation dialog. The address/copy control IDs are consecutive so the
 * handler can index them as DON_ADDR_BASE + row. */
#define IDD_DONATE        200
#define IDC_DON_TITLE     1100
#define IDC_DON_NOTE      1101
#define DON_LABEL_BASE    1110
#define DON_ADDR_BASE     1120
#define DON_COPY_BASE     1130
#define DON_COUNT         6

#endif
