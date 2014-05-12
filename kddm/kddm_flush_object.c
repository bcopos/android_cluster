/** KDDM flush object
 *  @file kddm_flush_object.c
 *
 *  Implementation of KDDM flush object function.
 *
 *  Copyright (C) 2001-2006, INRIA, Universite de Rennes 1, EDF.
 *  Copyright (C) 2006-2007, Renaud Lottiaux, Kerlabs.
 */
#include <linux/module.h>

#include <kddm/kddm.h>
#include <kddm/object_server.h>
#include "protocol_action.h"


/** Remove an object from local physical memory.
 *  @author Renaud Lottiaux
 *
 *  @param set        KDDM set hosting the object.
 *  @param objid      Identifier of the object to flush.
 *  @param dest       Identifier of the node to send object to if needed.
 *  @return           0 if everything OK, -1 otherwise.
 *
 *  Remove an object from local memory and send it to the given node if
 *  needed. At least one copy is kept somewhere in the cluster memory. The
 *  object is never swaped to disk through this function.
 */
int _kddm_flush_object(struct kddm_set *set,
		       objid_t objid,
		       kerrighed_node_t dest)
{
	kerrighed_node_t dest_from_copyset;
	struct kddm_obj *obj_entry;
	int res = -ENOENT;

	BUG_ON(!set);

	inc_flush_object_counter(set);

	obj_entry = __get_kddm_obj_entry(set, objid);
	if (obj_entry == NULL)
		return res;

try_again:
	switch (OBJ_STATE(obj_entry)) {
	case READ_COPY:
		if (object_frozen_or_pinned(obj_entry, set)) {
			__sleep_on_kddm_obj(set, obj_entry, objid, 0);
			goto try_again;
		}

		/* There exist another copy in the cluster.
		   Just invalidate the local one */
		destroy_kddm_obj_entry(set, obj_entry, objid, 0);
		send_invalidation_ack(set, objid, get_prob_owner(obj_entry));
		res = 0;
		goto exit_no_unlock;

	case READ_OWNER:
		if (object_frozen_or_pinned(obj_entry, set)) {
			__sleep_on_kddm_obj(set, obj_entry, objid, 0);
			goto try_again;
		}

		REMOVE_FROM_SET(COPYSET(obj_entry), kerrighed_node_id);
		if (SET_IS_EMPTY(COPYSET(obj_entry))) {
			/* I'm owner of the only existing object in the
			 * cluster. Let's inject it ! */
			goto send_copy;
		}
		/* There exist at least another copy. Send ownership */
		dest_from_copyset = choose_injection_node_in_copyset(obj_entry);
		BUG_ON (dest_from_copyset == -1);
		send_change_ownership_req(set, obj_entry, objid,
					  dest_from_copyset,
					  &obj_entry->master_obj);

		/* Wait for ack... The object is invalidated by the ack
		   handler */

		__sleep_on_kddm_obj(set, obj_entry, objid, 0);

		destroy_kddm_obj_entry(set, obj_entry, objid, 0);
		res = 0;
		goto exit_no_unlock;

	case WRITE_GHOST:
	case WRITE_OWNER:
		/* Local copy is the only one. Let's inject it ! */
send_copy:
		if (dest == KERRIGHED_NODE_ID_NONE) {
			res = -ENOSPC;
			break;
		}

		if (object_frozen_or_pinned(obj_entry, set)) {
			__sleep_on_kddm_obj(set, obj_entry, objid, 0);
			goto try_again;
		}

		send_copy_on_write(set, obj_entry, objid, dest,
				   KDDM_REMOVE_ON_ACK | KDDM_IO_FLUSH);
		res = 0;
		goto exit_no_unlock;

	case WAIT_ACK_INV:
	case WAIT_OBJ_RM_DONE:
	case WAIT_OBJ_RM_ACK:
	case WAIT_OBJ_RM_ACK2:
		res = 0;
		break;

	case INV_OWNER:
	case INV_COPY:
	case WAIT_ACK_WRITE:
	case WAIT_CHG_OWN_ACK:
	case WAIT_OBJ_READ:
	case WAIT_OBJ_WRITE:
	case INV_FILLING:
		break;

	default:
		STATE_MACHINE_ERROR(set->id, objid, obj_entry);
		break;
	}
	put_kddm_obj_entry(set, obj_entry, objid);

exit_no_unlock:

	return res;
}
EXPORT_SYMBOL(_kddm_flush_object);



int kddm_flush_object(struct kddm_ns *ns, kddm_set_id_t set_id, objid_t objid,
		      kerrighed_node_t dest)
{
	struct kddm_set *set;
	int res;

	set = _find_get_kddm_set (ns, set_id);
	res = _kddm_flush_object(set, objid, dest);
	put_kddm_set(set);

	return res;
}
EXPORT_SYMBOL(kddm_flush_object);
