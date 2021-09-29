#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/rtnetlink.h>
#include <linux/skbuff.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>

#include <linux/tc_act/tc_vlan.h>
#include <net/tc_act/tc_vlan.h>

static unsigned int add_field_net_id;
static struct tc_action_ops act_add_field_ops;

static int tcf_add_field_act(struct sk_buff *skb, const struct tc_action *a,
			                  struct tcf_result *res)
{
    return 0;
}            

static const struct nla_policy add_field_policy[TCA_ADD_FIELD_MAX + 1] = {
	[TCA_ADD_FIELD_PARMS]	          = { .len =  sizeof(struct tc_add_field) },
	//[TCA_ADD_FIELD_OFFSET]	      = ,
	//[TCA_ADD_FIELD_LEN]	          = ,
	//[TCA_ADD_FIELD_VALUE]		      = ,
};

static int tcf_add_field_init(struct net *net, struct nlattr *nla,
                              struct nlattr *est, struct tc_action **a,
                              int ovr, int bind, bool rtnl_held,
                              struct netlink_ext_ack *extack)
{
    struct tc_action_net *tn = net_generic(net, add_field_net_id);
    struct nlattr *tb[TCA_ADD_FIELD_MAX + 1]; // 目录 /include/uapi/linux/tc_act/tc_mpls.h
    struct tcf_add_field_params *p;
    struct tc_add_field *parm;
    bool exists = false;
    struct tcf_add_field *m;
    
	int ret = 0, err;
    u32 index;
        
    if (!nla) {
		NL_SET_ERR_MSG_MOD(extack, "Missing netlink attributes");
		return -EINVAL;
	}
        
    err = nla_parse_nested(tb, TCA_ADD_FIELD_MAX, nla, add_field_policy, NULL); // extack -> NULL (5.8.12 -> 4.19.206)
    if (err < 0)
		return err;
    if (!tb[TCA_ADD_FIELD_PARMS]) {
		NL_SET_ERR_MSG_MOD(extack, "No ADD FIELD params");
		return -EINVAL;
    }
	parm = nla_data(tb[TCA_ADD_FIELD_PARMS]);// params
	index = parm->index;
    err = tcf_idr_check_alloc(tn, &index, a, bind);
    if (err < 0)
		return err;
    exists = err;
	if (exists && bind)
		return 0;

	if (!exists) {
		ret = tcf_idr_create(tn, index, est, a,
				            &act_add_field_ops, bind, true);
		if (ret) {
			tcf_idr_cleanup(tn, index);
	        return ret;
        }

		ret = ACT_P_CREATED;
    } else if (!ovr) {
		tcf_idr_release(*a, bind);
		return -EEXIST;
	}
                
    m = to_add_field(*a);
          
    p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (!p) {
        tcf_idr_release(*a, bind);
		return -ENOMEM;
	} 
        
    p->tcfa_offset = nla_get_u16(tb[TCA_ADD_FIELD_OFFSET]);
    p->tcfa_len = nla_get_u16(tb[TCA_ADD_FIELD_LEN]);
    strcpy(p->tcfa_value, nla_data(tb[TCA_ADD_FIELD_VALUE])); // 将字符串指针赋值给数组
	printk(KERN_ALERT "Do the act_add_field_init!");
	printk(KERN_ALERT "tcfa_offset : %d", p->tcfa_offset);
	printk(KERN_DEBUG "tcfa_len : %d", p->tcfa_len);
	printk(KERN_DEBUG "tcfa_value[0] : %d, tcfa_value[1] : %d,", p->tcfa_value[0], p->tcfa_value[1]);
	printk(KERN_DEBUG "tcfa_value[2] : %d, tcfa_value[3] : %d\n", p->tcfa_value[2], p->tcfa_value[3]);
         
    spin_lock_bh(&m->tcf_lock); //  m->common.tcfa_lock
	rcu_swap_protected(m->add_field_p, p, lockdep_is_held(&m->tcf_lock));
	spin_unlock_bh(&m->tcf_lock); //
        
	if (p)
		kfree_rcu(p, rcu);

	if (ret == ACT_P_CREATED)
		tcf_idr_insert(tn, *a);
    return ret;                                                                
}

static void tcf_add_field_cleanup(struct tc_action *a)
{
	struct tcf_add_field *v = to_add_field(a);
	struct tcf_add_field_params *p;

	p = rcu_dereference_protected(v->add_field_p, 1);
	if (p)
		kfree_rcu(p, rcu);
}

static int tcf_add_field_dump(struct sk_buff *skb, struct tc_action *a,
			                        int bind, int ref)
{
    return 0;
}

static int tcf_add_field_walker(struct net *net, struct sk_buff *skb,
                                struct netlink_callback *cb, int type,
                                const struct tc_action_ops *ops,
                                struct netlink_ext_ack *extack)
{
    struct tc_action_net *tn = net_generic(net, add_field_net_id);

	return tcf_generic_walker(tn, skb, cb, type, ops, extack);
}

static int tcf_add_field_search(struct net *net, struct tc_action **a, u32 index,
                                struct netlink_ext_ack *extack)
{
    struct tc_action_net *tn = net_generic(net, add_field_net_id);

	return tcf_idr_search(tn, a, index);
}

static size_t tcf_add_field_get_fill_size(const struct tc_action *act)
{
	return nla_total_size(sizeof(struct tc_add_field))
		+ nla_total_size(sizeof(u16)) /* TCA_ADD_FIELD_OFFSET */
		+ nla_total_size(sizeof(u16)) /* TCA_ADD_FIELD_LEN */
		+ 16 * nla_total_size(sizeof(u8)); /* TCA_ADD_FIELD_VALUE */
}

static struct tc_action_ops act_add_field_ops = {
    .kind          =       "add_field",
    .type          =       TCA_ACT_ADD_FIELD, // belong to /include/uapi/linux/tc_act/tc_add_field.h
    .owner         =       THIS_MODULE,
    .act           =       tcf_add_field_act,
    .dump          =       tcf_add_field_dump,
    .init          =       tcf_add_field_init,
    .cleanup       =       tcf_add_field_cleanup,
    .walk          =       tcf_add_field_walker,
    .get_fill_size =       tcf_add_field_get_fill_size,
    .lookup        =       tcf_add_field_search,
    .size          =       sizeof(struct tcf_add_field),
};  

static __net_init int add_field_init_net(struct net *net)
{
	struct tc_action_net *tn = net_generic(net, add_field_net_id);

	return tc_action_net_init(net, tn, &act_add_field_ops);
}

static void __net_exit add_field_exit_net(struct list_head *net_list)
{
	tc_action_net_exit(net_list, add_field_net_id);
}

static struct pernet_operations add_field_net_ops = {
	.init = add_field_init_net,
	.exit_batch = add_field_exit_net,
	.id   = &add_field_net_id,
	.size = sizeof(struct tc_action_net),
};

static int __net_init add_field_init_module(void)
{
	printk(KERN_ALERT "Hello world enter!\n"); // cf: test
    return tcf_register_action(&act_add_field_ops, &add_field_net_ops); 
}

static void __net_exit add_field_cleanup_module(void)
{
	tcf_unregister_action(&act_add_field_ops, &add_field_net_ops);
    printk(KERN_ALERT "Hello world exit...\n"); // cf:test
}

module_init(add_field_init_module);
module_exit(add_field_cleanup_module);

MODULE_AUTHOR("cf");
MODULE_DESCRIPTION("add field manipulation actions");
MODULE_LICENSE("GPL v2");