/*
 * Copyright (C) 2011 Rodolfo Giometti <giometti@linux.it>
 * Copyright (C) 2011 CAEN RFID <info@caenrfid.it>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Library General Public
 *  License as published by the Free Software Foundation version 2
 *  of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Library General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this package; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 */

#ifndef _AVP_H
#define _AVP_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <arpa/inet.h>

/* Conversion interfaces.  */
#include <bits/byteswap.h>

#define ANTENNA_STR_LEN		24
#define EPC_DATA_LEN		64
#define MAX_TAG_VALUE_LEN       132

/*
 * Misc macros
 */

#define __deprecated		__attribute__ ((deprecated))
#define __packed		__attribute__ ((packed))
#define __constructor		__attribute__ ((constructor))

#define unlikely(x)		__builtin_expect(!!(x), 0)

/*
 * Errors AVP
 */

#define AVP_ERR_SUCCESS			0
#define AVP_ERR_UNKNOWN			102
#define AVP_ERR_INVALIDCMD		127
#define AVP_ERR_PWROUTRANGE		183
#define AVP_ERR_INVALIDPAR		200
#define AVP_ERR_TAGNOTPRESENT		202
#define AVP_ERR_TAGWRITE		203
#define AVP_ERR_TAGREAD			204
#define AVP_ERR_TAGBADADDRESS		205
#define AVP_ERR_INVALIDFUNCTION		206
#define AVP_ERR_TAGLOCK			209
#define AVP_ERR_TAGKILL			210

/*
 * AVP definitions
 */

#define __AVP_COMMON_FIELDS	uint16_t reserved;	\
				uint16_t len;		\
				uint16_t type;

/* AVP generic header */
struct avp_generic {
	__AVP_COMMON_FIELDS
	uint8_t data[0];
} __packed;

struct avp_command {
	__AVP_COMMON_FIELDS
	uint16_t cmd;
} __packed;
#define AVP_COMMAND		0x01

struct avp_result_code {
	__AVP_COMMON_FIELDS
	uint16_t code;
} __packed;
#define AVP_RESULT_CODE		0x02

struct avp_tag_id_len {
	__AVP_COMMON_FIELDS
	uint16_t id_len;
} __packed;
#define AVP_TAGIDLEN		0x0F

struct avp_timestamp {
	__AVP_COMMON_FIELDS
	uint32_t secs;
	uint32_t u_secs;
} __packed;
#define AVP_TIMESTAMP		0x10

struct avp_tag_id {
	__AVP_COMMON_FIELDS
	uint8_t id[0];
} __packed;
#define AVP_TAGID		0x11

struct avp_tag_type {
	__AVP_COMMON_FIELDS
	uint16_t tag_t;
} __packed;
#define AVP_TAGTYPE		0x12	/* short - Ver. 2.3 */

struct avp_readpoint_name {
	__AVP_COMMON_FIELDS
	char *name[0];
} __packed;
#define AVP_READPOINT_NAME	0x22

struct avp_tag_value {
	__AVP_COMMON_FIELDS
	uint8_t data[0];
} __packed;
#define AVP_TAG_VALUE		0x4D

struct avp_tag_address {
	__AVP_COMMON_FIELDS
	uint16_t addr;
} __packed;
#define AVP_TAGADDRESS		0x4E

struct avp_length {
	__AVP_COMMON_FIELDS
	uint16_t length;
} __packed;
#define AVP_LENGTH		0x50

struct avp_modulation {
	__AVP_COMMON_FIELDS
	uint16_t mod;
} __packed;
#define AVP_MODULATION		0x51
enum {
	AIR_MODULATION_DSB_ASK_FM0_TX10RX10 = 0,
	AIR_MODULATION_DSB_ASK_FM0_TX10RX40,
	AIR_MODULATION_DSB_ASK_FM0_TX40RX40,
	AIR_MODULATION_DSB_ASK_FM0_TX40RX160,
	AIR_MODULATION_DSB_ASK_FM0_TX160RX400,
	AIR_MODULATION_DSB_ASK_M2_TX40RX160,
	AIR_MODULATION_PR_ASK_M4_TX40RX250,
	AIR_MODULATION_PR_ASK_M4_TX40RX300,
	AIR_MODULATION_PR_ASK_M2_TX40RX250,
	AIR_MODULATION_PR_ASK_FM0_TX40RX40,
	__AIR_MODULATION_END
};

struct avp_power_value {
	__AVP_COMMON_FIELDS
	uint32_t power;
} __packed;
#define AVP_POWER_GET		0x52
#define AVP_POWER		0x96	/* FIXME: different AVP??? =:-o */

struct avp_protocol {
	__AVP_COMMON_FIELDS
	uint32_t proto;
} __packed;
#define AVP_PROTOCOL_NAME	0x54
enum {
	AIR_PROTOCOL_ISO18KB = 0,
	AIR_PROTOCOL_EPCGLOBAL_CLASS1_GEN1,
	AIR_PROTOCOL_ISO18KA,
	AIR_PROTOCOL_EPCGLOBAL_CLASS1_GEN2,
	AIR_PROTOCOL_CAEN_MULTIPR,
	AIR_PROTOCOL_EPCGLOBAL_CLASS119,
	AIR_PROTOCOL_UNSPECIFIED = 255,
	__AIR_PROTOCOL_END
};

struct avp_readpoint_status {
	__AVP_COMMON_FIELDS
	uint32_t status;	/* FIXME: can use uint8_t ? */
} __packed;
#define AVP_READPOINT_STATUS	0x56
enum {
	ANTENNA_STATUS_GOOD = 0,
	ANTENNA_STATUS_POOR,
	ANTENNA_STATUS_BAD,
	__ANTENNA_STATUS_END
};

struct avp_boolean {
	__AVP_COMMON_FIELDS
	uint16_t value;		/* FIXME: can use uint8_t ? */
} __packed;
#define AVP_BOOLEAN		0x57

struct avp_fw_release {
	__AVP_COMMON_FIELDS
	char *release[0];
} __packed;
#define AVP_GETFWRELEASE	0x5c

struct avp_rf_onoff {
	__AVP_COMMON_FIELDS
	uint16_t status;
} __packed;
#define AVP_RF_ONOFF		0x5f

struct avp_bitmask {
	__AVP_COMMON_FIELDS
	uint16_t value;
} __packed;
#define AVP_BITMASK		0x67	/* short  - Ver. 1.1 */

struct avp_io_register {
	__AVP_COMMON_FIELDS
	uint32_t value;
} __packed;
#define AVP_IOREGISTER		0x69	/* long   - Ver. 1.1 */

struct avp_src_conf_parameter {
	__AVP_COMMON_FIELDS
	uint32_t par;
} __packed;
#define AVP_SRCCONFPAR		0x6a
enum {
	SRC_CONF_PAR_READCYCLES = 0,
	SRC_CONF_PAR_OBSTHR,
	SRC_CONF_PAR_LOSTTHR,
	SRC_CONF_PAR_G2Q,
	SRC_CONF_PAR_G2SESSION,
	SRC_CONF_PAR_G2TARGET,
	SRC_CONF_PAR_G2SELECTED,
	SRC_CONF_PAR_ISOBDESB,
	SRC_CONF_PAR_DWELLTIME,
	SRC_CONF_PAR_INVALGO,
	SRC_CONF_PAR_INVCNT,
	SRC_CONF_PAR_G2QMIN,
	SRC_CONF_PAR_G2QMAX,
	SRC_CONF_PAR_TIDLEN,
	__SRC_CONF_PAR_END
};

struct avp_src_conf_value {
	__AVP_COMMON_FIELDS
	uint32_t value;
} __packed;
#define AVP_SRCCONFVAL		0x6b

struct avp_event_mode {
	__AVP_COMMON_FIELDS
	uint16_t mode;
} __packed;
#define AVP_EVENTMODE		0x6e
enum {
	EVENT_MODE_READCYCLE = 0,
	EVENT_MODE_TIME,
	EVENT_MODE_NO_EVENT,
	__EVENT_MODE_END
};

struct avp_membank {
	__AVP_COMMON_FIELDS
	uint16_t bank;
} __packed;
#define AVP_MEMBANK		0x71
enum {
	MEMORY_BANK_RESERVED = 0,	
	MEMORY_BANK_EPC,
	MEMORY_BANK_TID,
	MEMORY_BANK_USER,
	__MEMORY_BANK_END
};

struct avp_g2_payload {
	__AVP_COMMON_FIELDS
	uint32_t payload;
} __packed;
#define AVP_G2PAYLOAD		0x72

struct avp_g2_password {
	__AVP_COMMON_FIELDS
	uint32_t pwd;
} __packed;
#define AVP_G2PWD		0x73

struct avp_g2_nsi {
	__AVP_COMMON_FIELDS
	uint16_t nsi;
} __packed;
#define AVP_G2NSI		0x74

struct avp_q_value {
	__AVP_COMMON_FIELDS
	uint16_t q;
} __packed;
#define AVP_G2Q			0x75

struct avp_readerinfo {
	__AVP_COMMON_FIELDS
	char *info[0];
} __packed;
#define AVP_READERINFO		0x76

struct avp_rf_regulation {
	__AVP_COMMON_FIELDS
	uint16_t reg;
} __packed;
#define AVP_RFREGULATION	0x77
enum {
	AIR_REGULATION_ETSI302208 = 0,
	AIR_REGULATION_ETSI300220,
	AIR_REGULATION_FCCUS,
	AIR_REGULATION_MALAYSIA,
	AIR_REGULATION_JAPAN,
	AIR_REGULATION_KOREA,
	AIR_REGULATION_AUSTRALIA,
	AIR_REGULATION_CHINA,
	AIR_REGULATION_TAIWAN,
	AIR_REGULATION_SINGAPORE,
	AIR_REGULATION_BRAZIL,
	__AIR_REGULATION_END
};

struct avp_rfchannel {
	__AVP_COMMON_FIELDS
	uint16_t ch;
} __packed;
#define AVP_RFCHANNEL		0x78

#define AVP_SUBCMD			  (0x79)  // 121 - char * - Ver. 2.9

struct avp_rssi {
	__AVP_COMMON_FIELDS
	uint16_t rssi;
} __packed;
#define AVP_RSSI		0x7a

struct avp_source_name {
	__AVP_COMMON_FIELDS
	char *name[0];
} __packed;
#define AVP_SOURCE_NAME		0xfb

/*
 * Exported functions
 */

extern void avp_add_cmd(struct msgbuff *buff, uint16_t cmd);
extern int avp_manage_command(struct msgbuff *buff, uint16_t *cmd);
extern void avp_add_result_code(struct msgbuff *buff, uint16_t code);
extern int avp_manage_result_code(struct msgbuff *buff, uint16_t *code);
extern void avp_add_tag_id_len(struct msgbuff *buff, uint16_t id_len);
extern int avp_manage_tag_id_len(struct msgbuff *buff, uint16_t *len);
extern void avp_add_timestamp(struct msgbuff *buff,
					uint32_t secs, uint32_t u_secs);
extern int avp_manage_timestamp(struct msgbuff *buff,
					uint32_t *secs, uint32_t *u_secs);
extern void avp_add_tag_id(struct msgbuff *buff, uint8_t *id, size_t len);
extern int avp_manage_tag_id(struct msgbuff *buff, uint8_t *id, size_t *len);
extern void avp_add_tag_type(struct msgbuff *buff, uint16_t tag_t);
extern int avp_manage_tag_type(struct msgbuff *buff, uint16_t *tag_t);
extern void avp_add_readpoint_name(struct msgbuff *buff, char *antenna,
					size_t len);
extern int avp_manage_readpoint_name(struct msgbuff *buff, char *antenna);
extern void avp_add_tag_value(struct msgbuff *buff, uint8_t *data, size_t len);
extern int avp_manage_tag_value(struct msgbuff *buff, uint8_t *data);
extern void avp_add_tag_address(struct msgbuff *buff, uint16_t addr);
extern int avp_manage_tag_address(struct msgbuff *buff, uint16_t *addr);
extern void avp_add_length(struct msgbuff *buff, uint16_t len);
extern int avp_manage_length(struct msgbuff *buff, uint16_t *len);
extern void avp_add_modulation(struct msgbuff *buff, uint16_t mod);
extern int avp_manage_modulation(struct msgbuff *buff, uint16_t *mod);
extern void avp_add_power_value_server(struct msgbuff *buff, uint32_t power);
extern int avp_manage_power_value_server(struct msgbuff *buff, uint32_t *power);
extern void avp_add_power_value_client(struct msgbuff *buff, uint32_t power);
extern int avp_manage_power_value_client(struct msgbuff *buff, uint32_t *power);
extern void avp_add_protocol(struct msgbuff *buff, uint32_t proto);
extern int avp_manage_protocol(struct msgbuff *buff, uint32_t *proto);
extern void avp_add_readpoint_status(struct msgbuff *buff, uint32_t status);
extern void avp_add_boolean(struct msgbuff *buff, uint16_t value);
extern int avp_manage_boolean(struct msgbuff *buff, uint16_t *value);
extern void avp_add_fw_release(struct msgbuff *buff, const char *release,
					size_t len);
extern int avp_manage_fw_release(struct msgbuff *buff, char *release,
					size_t len);
extern int avp_manage_rf_onoff(struct msgbuff *buff, uint16_t *status);
extern void avp_add_bitmask(struct msgbuff *buff, uint16_t value);
extern int avp_manage_bitmask(struct msgbuff *buff, uint16_t *value);
extern void avp_add_io_register(struct msgbuff *buff, uint32_t value);
extern int avp_manage_io_register(struct msgbuff *buff, uint32_t *value);
extern void avp_add_src_conf_parameter(struct msgbuff *buff, uint32_t par);
extern int avp_manage_src_conf_parameter(struct msgbuff *buff, uint32_t *par);
extern void avp_add_src_conf_value(struct msgbuff *buff, uint32_t value);
extern int avp_manage_src_conf_value(struct msgbuff *buff, uint32_t *value);
extern void avp_add_event_mode(struct msgbuff *buff, uint16_t mode);
extern void avp_add_membank(struct msgbuff *buff, uint16_t bank);
extern int avp_manage_membank(struct msgbuff *buff, uint16_t *bank);
extern void avp_add_g2_password(struct msgbuff *buff, uint32_t pwd);
extern void avp_add_g2_payload(struct msgbuff *buff, uint32_t payload);
extern int avp_manage_g2_payload(struct msgbuff *buff, uint32_t *payload);
extern int avp_manage_g2_password(struct msgbuff *buff, uint32_t *pwd);
extern int avp_manage_g2_nsi(struct msgbuff *buff, uint16_t *nsi);
extern void avp_add_q_value(struct msgbuff *buff, uint16_t q);
extern int avp_manage_q_value(struct msgbuff *buff, uint16_t *q);
extern void avp_add_readerinfo(struct msgbuff *buff, char *info, size_t len);
extern void avp_add_regulation(struct msgbuff *buff, uint16_t reg);
extern int avp_manage_regulation(struct msgbuff *buff, uint16_t *ch);
extern void avp_add_rfchannel(struct msgbuff *buff, uint16_t ch);
extern int avp_manage_rfchannel(struct msgbuff *buff, uint16_t *ch);
extern void avp_add_rssi(struct msgbuff *buff, uint16_t rssi);
extern int avp_manage_rssi(struct msgbuff *buff, uint16_t *rssi);
extern void avp_add_source_name(struct msgbuff *buff, char *source, size_t len);
extern int avp_manage_source_name(struct msgbuff *buff, char *source);

#endif /* _AVP_H */
