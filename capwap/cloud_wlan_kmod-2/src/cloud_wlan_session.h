#ifndef CLOUD_WLAN_SESSION_H_
#define CLOUD_WLAN_SESSION_H_

/*
typedef struct cwlan_flow_session_cfg
{
	u32 over_time;				//��㳬ʱʱ�䣬����Ϊ��λ
	u32 interval_timer;		//��ʱ��ִ�м��ʱ�䣬����Ϊ��λ
	u32 flow_max;		//�������������ֽڼ�
	u32 del_time;		//�û�ɾ�����ʱ��
}cwlan_flow_session_cfg_t;
*/

#define CWLAN_FLOW_SESSION_HASH_LEN 200



typedef struct cloud_wlan_quintuple
{
	struct ethhdr eth_hd;
	struct iphdr ip_hd;
	//struct tcphdr tcp_hd;
	s32 skb_data_len;
}cloud_wlan_quintuple_s;

typedef struct pkt_tuple_info
{
	u8 smac[6];				//Ωһȷ��һ���û�
	u32 saddr;
	u32 daddr;
	u16 source;
	u16 dest;
	u8 protocol;
}pkt_tuple_info_t;

typedef struct cwlan_flow_session_node
{
	struct list_head list;
	pkt_tuple_info_t original_tuple;
	u32 status;				//�������״̬up down
	u64 add_time;		//����½�ʱ��
	u64 last_access_time;		//���һ�η���ʱ��
	u64 flow_B;				//ʹ�õ��������ֽڼ�
	s32 fragment_num;		//�յ�������Ƭ��Ҫ��һ��ack
}cwlan_flow_session_node_t;

typedef struct cwlan_flow_session_hash
{
	struct list_head h_head;	
	rwlock_t rwlock;
}cwlan_flow_session_hash_t;

extern cwlan_flow_session_hash_t *g_flow_session_hash;

/*�Ժ����֧���û���Զ������*/
extern cwlan_flow_session_cfg_t g_cw_fs_cfg;

extern u32 flow_session_match_online_list(cloud_wlan_quintuple_s *quintuple_info);
extern u32 flow_session_show_online_list(void);
extern u32 flow_session_up_node(cloud_wlan_quintuple_s *quintuple_info);
extern u32 flow_session_down_node(cloud_wlan_quintuple_s *quintuple_info);

//extern u32 flow_session_tcp_fragment_clr(cloud_wlan_quintuple_s *quintuple_info);
//extern u32 flow_session_tcp_fragment_inc(cloud_wlan_quintuple_s *quintuple_info);
extern u32 flow_sesison_init(void);
extern u32 flow_session_exit(void);


#endif /* READ_PA_INI_H_ */
