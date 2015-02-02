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

#include <msgbuff.h>

#include "avp.h"
#include "logging.h"
#include "macros.h"

/*
 * AVP management functions
 */

void avp_add_cmd(struct msgbuff *buff, uint16_t cmd)
{
	struct avp_command *c;

	c = msgbuff_push_tail(buff, sizeof(*c));
	BUG_ON(!c);

	c->reserved = 0;
	c->len = htobe16(sizeof(*c));
	c->type = htobe16(AVP_COMMAND);
	c->cmd = htobe16(cmd);
}

int avp_manage_command(struct msgbuff *buff, uint16_t *cmd)
{
	struct avp_command *e;

	e = msgbuff_pull_head(buff, sizeof(*e));
	if (!e)
		return -EINVAL;

	/* Sanity checks */
	if (e->type != htobe16(AVP_COMMAND))
		goto error;
	if (e->len != htobe16(sizeof(*e)))
		goto error;

	*cmd = be16toh(e->cmd);

	return 0;

error:
	msgbuff_push_head(buff, sizeof(*e));
	return -EINVAL;
}

void avp_add_result_code(struct msgbuff *buff, uint16_t code)
{
	struct avp_result_code *rc;

	rc = msgbuff_push_tail(buff, sizeof(*rc));
	BUG_ON(!rc);

	rc->reserved = 0;
	rc->len = htobe16(sizeof(*rc));
	rc->type = htobe16(AVP_RESULT_CODE);
	rc->code = htobe16(code);
}

int avp_manage_result_code(struct msgbuff *buff, uint16_t *code)
{
	struct avp_result_code *rc;

	rc = msgbuff_pull_head(buff, sizeof(*rc));
	if (!rc)
		return -EINVAL;

	/* Sanity checks */
	if (rc->type != htobe16(AVP_RESULT_CODE))
		goto error;
	if (rc->len != htobe16(sizeof(*rc)))
		goto error;

	*code = be16toh(rc->code);

	return 0;

error:
	msgbuff_push_head(buff, sizeof(*rc));
	return -EINVAL;
}

void avp_add_tag_id_len(struct msgbuff *buff, uint16_t id_len)
{
	struct avp_tag_id_len *tag;

	tag = msgbuff_push_tail(buff, sizeof(*tag));
	BUG_ON(!tag);

	tag->reserved = 0;
	tag->len = htobe16(sizeof(*tag));
	tag->type = htobe16(AVP_TAGIDLEN);
	tag->id_len = htobe16(id_len);
}

int avp_manage_tag_id_len(struct msgbuff *buff, uint16_t *len)
{
	struct avp_tag_id_len *tag;

	tag = msgbuff_pull_head(buff, sizeof(*tag));
	if (!tag)
		return -EINVAL;

	/* Sanity checks */
	if (tag->type != htobe16(AVP_TAGIDLEN))
		goto error;
	if (be16toh(tag->len) > sizeof(*tag))
		goto error;

	*len = be16toh(tag->id_len);

	return 0;

error:
	msgbuff_push_head(buff, sizeof(*tag));
	return -EINVAL;
}

void avp_add_timestamp(struct msgbuff *buff,
					uint32_t secs, uint32_t u_secs)
{
	struct avp_timestamp *ts;

	ts = msgbuff_push_tail(buff, sizeof(*ts));
	BUG_ON(!ts);

	ts->reserved = 0;
	ts->len = htobe16(sizeof(*ts));
	ts->type = htobe16(AVP_TIMESTAMP);
	ts->secs = htobe32(secs);
	ts->u_secs = htobe32(u_secs);
}

int avp_manage_timestamp(struct msgbuff *buff,
					uint32_t *secs, uint32_t *u_secs)
{
	struct avp_timestamp *ts;

	ts = msgbuff_pull_head(buff, sizeof(*ts));
	if (!ts)
		return -EINVAL;

	/* Sanity checks */
	if (ts->type != htobe16(AVP_TIMESTAMP))
		goto error;
	if (ts->len != htobe16(sizeof(*ts)))
		goto error;

	*secs = be32toh(ts->secs);
	*u_secs = be32toh(ts->u_secs);

	return 0;

error:
	msgbuff_push_head(buff, sizeof(*ts));
	return -EINVAL;
}

void avp_add_tag_id(struct msgbuff *buff, uint8_t *id, size_t len)
{
	struct avp_tag_id *tag;

	tag = msgbuff_push_tail(buff, sizeof(*tag) + len);
	BUG_ON(!tag);

	tag->reserved = 0;
	tag->len = htobe16(sizeof(*tag) + len);
	tag->type = htobe16(AVP_TAGID);
	memcpy(tag->id, id, len);
}

int avp_manage_tag_id(struct msgbuff *buff, uint8_t *id, size_t *len)
{
	struct avp_tag_id *tag;

	tag = msgbuff_pull_head(buff, sizeof(*tag));
	if (!tag)
		return -EINVAL;

	/* Sanity checks */
	if (tag->type != htobe16(AVP_TAGID))
		goto error;
	if (be16toh(tag->len) > sizeof(*tag) + EPC_DATA_LEN)
		goto error;

	*len = be16toh(tag->len) - sizeof(*tag);
	memcpy(id, tag->id, *len);

	/* Drop the tag ID */
	msgbuff_pull_head(buff, *len);

	return 0;

error:
	msgbuff_push_head(buff, sizeof(*tag));
	return -EINVAL;
}

void avp_add_tag_type(struct msgbuff *buff, uint16_t tag_t)
{
	struct avp_tag_type *tag;

	tag = msgbuff_push_tail(buff, sizeof(*tag));
	BUG_ON(!tag);

	tag->reserved = 0;
	tag->len = htobe16(sizeof(*tag));
	tag->type = htobe16(AVP_TAGTYPE);
	tag->tag_t = htobe16(tag_t);
}

int avp_manage_tag_type(struct msgbuff *buff, uint16_t *tag_t)
{
	struct avp_tag_type *tag;

	tag = msgbuff_pull_head(buff, sizeof(*tag));
	if (!tag)
		return -EINVAL;

	/* Sanity checks */
	if (tag->type != htobe16(AVP_TAGTYPE))
		goto error;
	if (tag->len != htobe16(sizeof(*tag)))
		goto error;

	*tag_t = be16toh(tag->tag_t);

	return 0;

error:
	msgbuff_push_head(buff, sizeof(*tag));
	return -EINVAL;
}

void avp_add_readpoint_name(struct msgbuff *buff, char *antenna,
					size_t len)
{
	struct avp_readpoint_name *rpt;

	rpt = msgbuff_push_tail(buff, sizeof(*rpt) + len);
	BUG_ON(!rpt);

	rpt->reserved = 0;
	rpt->len = htobe16(sizeof(*rpt) + len);
	rpt->type = htobe16(AVP_READPOINT_NAME);
	memcpy(rpt->name, antenna, len);
}

int avp_manage_readpoint_name(struct msgbuff *buff, char *antenna)
{
	struct avp_readpoint_name *rpt;
	size_t len;

	rpt = msgbuff_pull_head(buff, sizeof(*rpt));
	if (!rpt)
		return -EINVAL;

	/* Sanity checks */
	if (rpt->type != htobe16(AVP_READPOINT_NAME))
		goto error;
	if (be16toh(rpt->len) > sizeof(*rpt) + ANTENNA_STR_LEN)
		goto error;

	len = be16toh(rpt->len) - sizeof(*rpt);
	memcpy(antenna, rpt->name, len);

	/* Drop the source name */
	msgbuff_pull_head(buff, len);

	return 0;

error:
	msgbuff_push_head(buff, sizeof(*rpt));
	return -EINVAL;
}

void avp_add_tag_value(struct msgbuff *buff, uint8_t *data, size_t len)
{
	struct avp_tag_value *tag;

	tag = msgbuff_push_tail(buff, sizeof(*tag) + len);
	BUG_ON(!tag);

	tag->reserved = 0;
	tag->len = htobe16(sizeof(*tag) + len);
	tag->type = htobe16(AVP_TAG_VALUE);
	memcpy(tag->data, data, len);
}

int avp_manage_tag_value(struct msgbuff *buff, uint8_t *data)
{
	struct avp_tag_value *tag;
	size_t len;

	tag = msgbuff_pull_head(buff, sizeof(*tag));
	if (!tag)
		return -EINVAL;

	/* Sanity checks */
	if (tag->type != htobe16(AVP_TAG_VALUE))
		goto error;
	if (be16toh(tag->len) > sizeof(*tag) + MAX_TAG_VALUE_LEN)
		goto error;

	len = be16toh(tag->len) - sizeof(*tag);
	memcpy(data, tag->data, len);

	/* Drop the source name */
	msgbuff_pull_head(buff, len);

	return 0;

error:
	msgbuff_push_head(buff, sizeof(*tag));
	return -EINVAL;
}

void avp_add_tag_address(struct msgbuff *buff, uint16_t addr)
{
	struct avp_tag_address *tag;

	tag = msgbuff_push_tail(buff, sizeof(*tag));
	BUG_ON(!tag);

	tag->reserved = 0;
	tag->len = htobe16(sizeof(*tag));
	tag->type = htobe16(AVP_TAGADDRESS);
	tag->addr = htobe16(addr);
}

int avp_manage_tag_address(struct msgbuff *buff, uint16_t *addr)
{
	struct avp_tag_address *tag;

	tag = msgbuff_pull_head(buff, sizeof(*tag));
	if (!tag)
		return -EINVAL;

	/* Sanity checks */
	if (tag->type != htobe16(AVP_TAGADDRESS))
		goto error;
	if (be16toh(tag->len) > sizeof(*tag))
		goto error;

	*addr = be16toh(tag->addr);

	return 0;

error:
	msgbuff_push_head(buff, sizeof(*tag));
	return -EINVAL;
}

void avp_add_length(struct msgbuff *buff, uint16_t len)
{
	struct avp_length *ptr;

	ptr = msgbuff_push_tail(buff, sizeof(*ptr));
	BUG_ON(!ptr);

	ptr->reserved = 0;
	ptr->len = htobe16(sizeof(*ptr));
	ptr->type = htobe16(AVP_LENGTH);
	ptr->length = htobe16(len);
}

int avp_manage_length(struct msgbuff *buff, uint16_t *len)
{
	struct avp_length *ptr;

	ptr = msgbuff_pull_head(buff, sizeof(*ptr));
	if (!ptr)
		return -EINVAL;

	/* Sanity checks */
	if (ptr->type != htobe16(AVP_LENGTH))
		goto error;
	if (be16toh(ptr->len) > sizeof(*ptr))
		goto error;

	*len = be16toh(ptr->length);

	return 0;

error:
	msgbuff_push_head(buff, sizeof(*ptr));
	return -EINVAL;
}

void avp_add_modulation(struct msgbuff *buff, uint16_t mod)
{
	struct avp_modulation *md;

	md = msgbuff_push_tail(buff, sizeof(*md));
	BUG_ON(!md);

	md->reserved = 0;
	md->len = htobe16(sizeof(*md));
	md->type = htobe16(AVP_MODULATION);
	md->mod = htobe16(mod);
}

int avp_manage_modulation(struct msgbuff *buff, uint16_t *mod)
{
	struct avp_modulation *md;

	md = msgbuff_pull_head(buff, sizeof(*md));
	if (!md)
		return -EINVAL;

	/* Sanity checks */
	if (md->type != htobe16(AVP_MODULATION))
		goto error;
	if (md->len != htobe16(sizeof(*md)))
		goto error;

	*mod = be16toh(md->mod);

	return 0;

error:
	msgbuff_push_head(buff, sizeof(*md));
	return -EINVAL;
}

/*
 * Hack-Hack-Hack!
 *
 * Due a broken-damaged(TM) specification into CAENRFID protocol (who
 * specifies that we must use two different AVPs for the "power" value)
 * we must define _different_ functions for the server and client side
 * of the power management functions...
 */
void avp_add_power_value_server(struct msgbuff *buff, uint32_t power)
{
	struct avp_power_value *pv;

	pv = msgbuff_push_tail(buff, sizeof(*pv));
	BUG_ON(!pv);

	pv->reserved = 0;
	pv->len = htobe16(sizeof(*pv));
	pv->type = htobe16(AVP_POWER_GET);
	pv->power = htobe32(power);
}

int avp_manage_power_value_server(struct msgbuff *buff, uint32_t *power)
{
	struct avp_power_value *pv;

	pv = msgbuff_pull_head(buff, sizeof(*pv));
	if (!pv)
		return -EINVAL;

	/* Sanity checks */
	if (pv->type != htobe16(AVP_POWER))
		goto error;
	if (pv->len != htobe16(sizeof(*pv)))
		goto error;

	*power = be32toh(pv->power);

	return 0;

error:
	msgbuff_push_head(buff, sizeof(*pv));
	return -EINVAL;
}

void avp_add_power_value_client(struct msgbuff *buff, uint32_t power)
{
	struct avp_power_value *pv;

	pv = msgbuff_push_tail(buff, sizeof(*pv));
	BUG_ON(!pv);

	pv->reserved = 0;
	pv->len = htobe16(sizeof(*pv));
	pv->type = htobe16(AVP_POWER);
	pv->power = htobe32(power);
}

int avp_manage_power_value_client(struct msgbuff *buff, uint32_t *power)
{
	struct avp_power_value *pv;

	pv = msgbuff_pull_head(buff, sizeof(*pv));
	if (!pv)
		return -EINVAL;

	/* Sanity checks */
	if (pv->type != htobe16(AVP_POWER_GET))
		goto error;
	if (pv->len != htobe16(sizeof(*pv)))
		goto error;

	*power = be32toh(pv->power);

	return 0;

error:
	msgbuff_push_head(buff, sizeof(*pv));
	return -EINVAL;
}

/* Hack-Hack-Hack! End... */

void avp_add_protocol(struct msgbuff *buff, uint32_t proto)
{
	struct avp_protocol *pn;

	pn = msgbuff_push_tail(buff, sizeof(*pn));
	BUG_ON(!pn);

	pn->reserved = 0;
	pn->len = htobe16(sizeof(*pn));
	pn->type = htobe16(AVP_PROTOCOL_NAME);
	pn->proto = htobe32(proto);
}

int avp_manage_protocol(struct msgbuff *buff, uint32_t *proto)
{
	struct avp_protocol *pn;

	pn = msgbuff_pull_head(buff, sizeof(*pn));
	if (!pn)
		return -EINVAL;

	/* Sanity checks */
	if (pn->type != htobe16(AVP_PROTOCOL_NAME))
		goto error;
	if (pn->len != htobe16(sizeof(*pn)))
		goto error;

	*proto = be32toh(pn->proto);

	return 0;

error:
	msgbuff_push_head(buff, sizeof(*pn));
	return -EINVAL;
}

void avp_add_readpoint_status(struct msgbuff *buff, uint32_t status)
{
	struct avp_readpoint_status *s;

	s = msgbuff_push_tail(buff, sizeof(*s));
	BUG_ON(!s);

	s->reserved = 0;
	s->len = htobe16(sizeof(*s));
	s->type = htobe16(AVP_READPOINT_STATUS);
	s->status = htobe32(status);
}

void avp_add_boolean(struct msgbuff *buff, uint16_t value)
{
	struct avp_boolean *b;

	b = msgbuff_push_tail(buff, sizeof(*b));
	BUG_ON(!b);
	b->len = htobe16(sizeof(*b));
	b->type = htobe16(AVP_BOOLEAN);
	b->value = htobe16(value);
}

int avp_manage_boolean(struct msgbuff *buff, uint16_t *value)
{
	struct avp_boolean *b;

	b = msgbuff_pull_head(buff, sizeof(*b));
	if (!b)
		return -EINVAL;

	/* Sanity checks */
	if (b->type != htobe16(AVP_BOOLEAN))
		goto error;
	if (b->len != htobe16(sizeof(*b)))
		goto error;

	*value = be16toh(b->value);

	return 0;

error:
	msgbuff_push_head(buff, sizeof(*b));
	return -EINVAL;
}

void avp_add_fw_release(struct msgbuff *buff, const char *release,
					size_t len)
{
	struct avp_fw_release *fw;

	fw = msgbuff_push_tail(buff, sizeof(*fw) + len);
	BUG_ON(!fw);

	fw->reserved = 0;
	fw->len = htobe16(sizeof(*fw) + len);
	fw->type = htobe16(AVP_GETFWRELEASE);
	memcpy(fw->release, release, len);
}

int avp_manage_fw_release(struct msgbuff *buff, char *release, size_t len)
{
	struct avp_fw_release *fw;
	int n;

	fw = msgbuff_pull_head(buff, sizeof(*fw));
	if (!fw)
		return -EINVAL;

	/* Sanity checks */
	if (fw->type != htobe16(AVP_GETFWRELEASE))
		goto error;
	if (be16toh(fw->len) > sizeof(*fw) + len)
		goto error;

	n = be16toh(fw->len) - sizeof(*fw);
	if (n <= 0)
		goto error;
	memcpy(release, fw->release, n);

	/* Drop the firmware release */
	msgbuff_pull_head(buff, n);

	return n;

error:
	msgbuff_push_head(buff, sizeof(*fw));
	return -EINVAL;
}

int avp_manage_rf_onoff(struct msgbuff *buff, uint16_t *status)
{
	struct avp_rf_onoff *rf;

	rf = msgbuff_pull_head(buff, sizeof(*rf));
	if (!rf)
		return -EINVAL;

	/* Sanity checks */
	if (rf->type != htobe16(AVP_RF_ONOFF))
		goto error;
	if (rf->len != htobe16(sizeof(*rf)))
		goto error;

	*status = be16toh(rf->status);

	return 0;

error:
	msgbuff_push_head(buff, sizeof(*rf));
	return -EINVAL;
}

void avp_add_bitmask(struct msgbuff *buff, uint16_t value)
{
	struct avp_bitmask *bm;

	bm = msgbuff_push_tail(buff, sizeof(*bm));
	BUG_ON(!bm);

	bm->reserved = 0;
	bm->len = htobe16(sizeof(*bm));
	bm->type = htobe16(AVP_BITMASK);
	bm->value = htobe16(value);
}

int avp_manage_bitmask(struct msgbuff *buff, uint16_t *value)
{
	struct avp_bitmask *bm;

	bm = msgbuff_pull_head(buff, sizeof(*bm));
	if (!bm)
		return -EINVAL;

	/* Sanity checks */
	if (bm->type != htobe16(AVP_BITMASK))
		goto error;
	if (bm->len != htobe16(sizeof(*bm)))
		goto error;

	*value = be16toh(bm->value);

	return 0;

error:
	msgbuff_push_head(buff, sizeof(*bm));
	return -EINVAL;
}

void avp_add_io_register(struct msgbuff *buff, uint32_t value)
{
	struct avp_io_register *io;

	io = msgbuff_push_tail(buff, sizeof(*io));
	BUG_ON(!io);

	io->reserved = 0;
	io->len = htobe16(sizeof(*io));
	io->type = htobe16(AVP_IOREGISTER);
	io->value = htobe32(value);
}

int avp_manage_io_register(struct msgbuff *buff, uint32_t *value)
{
	struct avp_io_register *io;

	io = msgbuff_pull_head(buff, sizeof(*io));
	if (!io)
		return -EINVAL;

	/* Sanity checks */
	if (io->type != htobe16(AVP_IOREGISTER))
		goto error;
	if (io->len != htobe16(sizeof(*io)))
		goto error;

	*value = be32toh(io->value);

	return 0;

error:
	msgbuff_push_head(buff, sizeof(*io));
	return -EINVAL;
}

void avp_add_src_conf_parameter(struct msgbuff *buff, uint32_t par)
{
	struct avp_src_conf_parameter *cfg;

	cfg = msgbuff_push_tail(buff, sizeof(*cfg));
	BUG_ON(!cfg);

	cfg->reserved = 0;
	cfg->len = htobe16(sizeof(*cfg));
	cfg->type = htobe16(AVP_SRCCONFPAR);
	cfg->par = htobe32(par);
}

int avp_manage_src_conf_parameter(struct msgbuff *buff, uint32_t *par)
{
	struct avp_src_conf_parameter *cfg;

	cfg = msgbuff_pull_head(buff, sizeof(*cfg));
	if (!cfg)
		return -EINVAL;

	/* Sanity checks */
	if (cfg->type != htobe16(AVP_SRCCONFPAR))
		goto error;
	if (cfg->len != htobe16(sizeof(*cfg)))
		goto error;

	*par = be32toh(cfg->par);

	return 0;

error:
	msgbuff_push_head(buff, sizeof(*cfg));
	return -EINVAL;
}

void avp_add_src_conf_value(struct msgbuff *buff, uint32_t value)
{
	struct avp_src_conf_value *cfg;

	cfg = msgbuff_push_tail(buff, sizeof(*cfg));
	BUG_ON(!cfg);

	cfg->reserved = 0;
	cfg->len = htobe16(sizeof(*cfg));
	cfg->type = htobe16(AVP_SRCCONFVAL);
	cfg->value = htobe32(value);
}

int avp_manage_src_conf_value(struct msgbuff *buff, uint32_t *value)
{
	struct avp_src_conf_value *cfg;

	cfg = msgbuff_pull_head(buff, sizeof(*cfg));
	if (!cfg)
		return -EINVAL;

	/* Sanity checks */
	if (cfg->type != htobe16(AVP_SRCCONFVAL))
		goto error;
	if (cfg->len != htobe16(sizeof(*cfg)))
		goto error;

	*value = be32toh(cfg->value);

	return 0;

error:
	msgbuff_push_head(buff, sizeof(*cfg));
	return -EINVAL;
}

void avp_add_event_mode(struct msgbuff *buff, uint16_t mode)
{
	struct avp_event_mode *ev;

	ev = msgbuff_push_tail(buff, sizeof(*ev));
	BUG_ON(!ev);

	ev->reserved = 0;
	ev->len = htobe16(sizeof(*ev));
	ev->type = htobe16(AVP_EVENTMODE);
	ev->mode = htobe16(mode);
}

void avp_add_membank(struct msgbuff *buff, uint16_t bank)
{
	struct avp_membank *mem;

	mem = msgbuff_push_tail(buff, sizeof(*mem));
	BUG_ON(!mem);

	mem->reserved = 0;
	mem->len = htobe16(sizeof(*mem));
	mem->type = htobe16(AVP_MEMBANK);
	mem->bank = htobe16(bank);
}

int avp_manage_membank(struct msgbuff *buff, uint16_t *bank)
{
	struct avp_membank *mem;

	mem = msgbuff_pull_head(buff, sizeof(*mem));
	if (!mem)
		return -EINVAL;

	/* Sanity checks */
	if (mem->type != htobe16(AVP_MEMBANK))
		goto error;
	if (mem->len != htobe16(sizeof(*mem)))
		goto error;

	*bank = be16toh(mem->bank);

	return 0;

error:
	msgbuff_push_head(buff, sizeof(*mem));
	return -EINVAL;
}

void avp_add_g2_payload(struct msgbuff *buff, uint32_t payload)
{
	struct avp_g2_payload *p;

	p = msgbuff_push_tail(buff, sizeof(*p));
	BUG_ON(!p);

	p->reserved = 0;
	p->len = htobe16(sizeof(*p));
	p->type = htobe16(AVP_G2PAYLOAD);
	p->payload = htobe32(payload);
}

int avp_manage_g2_payload(struct msgbuff *buff, uint32_t *payload)
{
	struct avp_g2_payload *p;

	p = msgbuff_pull_head(buff, sizeof(*p));
	if (!p)
		return -EINVAL;

	/* Sanity checks */
	if (p->type != htobe16(AVP_G2PAYLOAD))
		goto error;
	if (p->len != htobe16(sizeof(*p)))
		goto error;

	*payload = be32toh(p->payload);

	return 0;

error:
	msgbuff_push_head(buff, sizeof(*p));
	return -EINVAL;
}

void avp_add_g2_password(struct msgbuff *buff, uint32_t pwd)
{
	struct avp_g2_password *p;

	p = msgbuff_push_tail(buff, sizeof(*p));
	BUG_ON(!p);

	p->reserved = 0;
	p->len = htobe16(sizeof(*p));
	p->type = htobe16(AVP_G2PWD);
	p->pwd = htobe32(pwd);
}

int avp_manage_g2_password(struct msgbuff *buff, uint32_t *pwd)
{
	struct avp_g2_password *p;

	p = msgbuff_pull_head(buff, sizeof(*p));
	if (!p)
		return -EINVAL;

	/* Sanity checks */
	if (p->type != htobe16(AVP_G2PWD))
		goto error;
	if (p->len != htobe16(sizeof(*p)))
		goto error;

	*pwd = be32toh(p->pwd);

	return 0;

error:
	msgbuff_push_head(buff, sizeof(*p));
	return -EINVAL;
}

int avp_manage_g2_nsi(struct msgbuff *buff, uint16_t *nsi)
{
	struct avp_g2_nsi *d;

	d = msgbuff_pull_head(buff, sizeof(*d));
	if (!d)
		return -EINVAL;

	/* Sanity checks */
	if (d->type != htobe16(AVP_G2NSI))
		goto error;
	if (d->len != htobe16(sizeof(*d)))
		goto error;

	*nsi = be16toh(d->nsi);

	return 0;

error:
	msgbuff_push_head(buff, sizeof(*d));
	return -EINVAL;
}

void avp_add_q_value(struct msgbuff *buff, uint16_t q)
{
	struct avp_q_value *qv;

	qv = msgbuff_push_tail(buff, sizeof(*qv));
	BUG_ON(!qv);

	qv->reserved = 0;
	qv->len = htobe16(sizeof(*qv));
	qv->type = htobe16(AVP_G2Q);
	qv->q = htobe16(q);
}

int avp_manage_q_value(struct msgbuff *buff, uint16_t *q)
{
	struct avp_q_value *qv;

	qv = msgbuff_pull_head(buff, sizeof(*qv));
	if (!qv)
		return -EINVAL;

	/* Sanity checks */
	if (qv->type != htobe16(AVP_G2Q))
		goto error;
	if (qv->len != htobe16(sizeof(*qv)))
		goto error;

	*q = be16toh(qv->q);

	return 0;

error:
	msgbuff_push_head(buff, sizeof(*qv));
	return -EINVAL;
}

void avp_add_readerinfo(struct msgbuff *buff, char *info, size_t len)
{
	struct avp_readerinfo *r;

	r = msgbuff_push_tail(buff, sizeof(*r) + len);
	BUG_ON(!r);

	r->reserved = 0;
	r->len = htobe16(sizeof(*r) + len);
	r->type = htobe16(AVP_READERINFO);
	memcpy(r->info, info, len);
}

void avp_add_regulation(struct msgbuff *buff, uint16_t reg)
{
	struct avp_rf_regulation *rf;

	rf = msgbuff_push_tail(buff, sizeof(*rf));
	BUG_ON(!rf);

	rf->reserved = 0;
	rf->len = htobe16(sizeof(*rf));
	rf->type = htobe16(AVP_RFREGULATION);
	rf->reg = htobe16(reg);
}

int avp_manage_regulation(struct msgbuff *buff, uint16_t *ch)
{
	struct avp_rf_regulation *rf;

	rf = msgbuff_pull_head(buff, sizeof(*rf));
	if (!rf)
		return -EINVAL;

	/* Sanity checks */
	if (rf->type != htobe16(AVP_RFREGULATION))
		goto error;
	if (rf->len != htobe16(sizeof(*rf)))
		goto error;

	*ch = be16toh(rf->reg);

	return 0;

error:
	msgbuff_push_head(buff, sizeof(*rf));
	return -EINVAL;
}

void avp_add_rfchannel(struct msgbuff *buff, uint16_t ch)
{
	struct avp_rfchannel *rf;

	rf = msgbuff_push_tail(buff, sizeof(*rf));
	BUG_ON(!rf);

	rf->reserved = 0;
	rf->len = htobe16(sizeof(*rf));
	rf->type = htobe16(AVP_RFCHANNEL);
	rf->ch = htobe16(ch);
}

int avp_manage_rfchannel(struct msgbuff *buff, uint16_t *ch)
{
	struct avp_rfchannel *rf;

	rf = msgbuff_pull_head(buff, sizeof(*rf));
	if (!rf)
		return -EINVAL;

	/* Sanity checks */
	if (rf->type != htobe16(AVP_RFCHANNEL))
		goto error;
	if (rf->len != htobe16(sizeof(*rf)))
		goto error;

	*ch = be16toh(rf->ch);

	return 0;

error:
	msgbuff_push_head(buff, sizeof(*rf));
	return -EINVAL;
}

void avp_add_rssi(struct msgbuff *buff, uint16_t rssi)
{
	struct avp_rssi *tag;

	tag = msgbuff_push_tail(buff, sizeof(*tag));
	BUG_ON(!tag);

	tag->reserved = 0;
	tag->len = htobe16(sizeof(*tag));
	tag->type = htobe16(AVP_RSSI);
	tag->rssi = htobe16(rssi);
}

int avp_manage_rssi(struct msgbuff *buff, uint16_t *rssi)
{
	struct avp_rssi *tag;

	tag = msgbuff_pull_head(buff, sizeof(*tag));
	if (!tag)
		return -EINVAL;

	/* Sanity checks */
	if (tag->type != htobe16(AVP_RSSI))
		goto error;
	if (be16toh(tag->len) > sizeof(*tag))
		goto error;

	*rssi = be16toh(tag->rssi);

	return 0;

error:
	msgbuff_push_head(buff, sizeof(*tag));
	return -EINVAL;
}

void avp_add_source_name(struct msgbuff *buff, char *source, size_t len)
{
	struct avp_source_name *src;

	src = msgbuff_push_tail(buff, sizeof(*src) + len);
	BUG_ON(!src);

	src->reserved = 0;
	src->len = htobe16(sizeof(*src) + len);
	src->type = htobe16(AVP_SOURCE_NAME);
	memcpy(src->name, source, len);
}

int avp_manage_source_name(struct msgbuff *buff, char *source)
{
	struct avp_source_name *src;
	size_t len;

	src = msgbuff_pull_head(buff, sizeof(*src));
	if (!src)
		return -EINVAL;

	/* Sanity checks */
	if (src->type != htobe16(AVP_SOURCE_NAME))
		goto error;
	if (be16toh(src->len) > sizeof(*src) + ANTENNA_STR_LEN)
		goto error;

	len = be16toh(src->len) - sizeof(*src);
	memcpy(source, src->name, len);

	/* Drop the source name */
	msgbuff_pull_head(buff, len);

	return 0;

error:
	msgbuff_push_head(buff, sizeof(*src));
	return -EINVAL;
}
