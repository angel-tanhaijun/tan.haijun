/*************************************************************************
	> File Name: offline_define_log.h
	> Author: tan.haijun
	> Mail: 013721@163.com 
	> Created Time: 2020年06月03日 星期三 16时05分24秒
 ************************************************************************/




#define OFFLINE_CONNECTLOG_DEVICE_TYPE                      (0x10000000)
#define OFFLINE_CONNECTLOG_DATA_TYPE                        (0x0001)
#define OFFLINE_CONNECTLOG_ATM_TYPE                         (0x10127001)
#define  offline_connectlog_atm_vpi_type                              (0x10127002)
#define  offline_connectlog_atm_vci_type                              (0x10127003)
#define  offline_connectlog_atm_pti_type                              (0x10127004)
#define  offline_connectlog_atm_all_type_type                         (0x10127005)

#define OFFLINE_CONNECTLOG_BASE_INFO_TYPE                       (0x10000001)
#define offline_connectlog_basic_sample_type                    (0x10000002)

#define OFFLINE_CONNECTLOG_USER_VENDOR_TYPE                     (0x10005001)
#define  offline_connectlog_normal_vendor_type                  (0x10005003)
#define  offline_connectlog_user_vendor_host_type               (0x10005005)     
#define  offline_connectlog_user_vendor_machine_name_type       (0x10005006)     
#define  offline_connectlog_user_vendor_user_name_type          (0x10005007)     
#define  offline_connectlog_user_vendor_cap_timestamp_type      (0x10005008)     
#define  offline_connectlog_user_vendor_analysis_timestamp_type (0x10005009)     
#define  offline_connectlog_user_vendor_session_id_type         (0x1000500A)     
#define  offline_connectlog_user_vendor_filename_type           (0x1000500B)     
#define  offline_connectlog_user_vendor_spe_info_type           (0x10005011)     
#define  offline_connectlog_user_vendor_channel_type           (0x10005012)      
#define  offline_connectlog_user_vendor_plug_info_type           (0x10005013)    
#define  offline_connectlog_user_vendor_spot_beam_type           (0x10005014)    
#define  offline_connectlog_user_vendor_tcpclienttime_type           (0x10005015)
#define  offline_connectlog_user_vendor_user_info_type           (0x10005016)    
#define  offline_connectlog_user_vendor_src_mac_type             (0x10005050)    
#define  offline_connectlog_user_vendor_dst_mac_type             (0x10005051)    


#define OFFLINE_CONNECTLOG_RX_MSG_TYPE                          (0x1001C001)
#define  offline_connectlog_device_info_type                    (0x1001C002)
#define  offline_connectlog_data_info_type                      (0x1001C003)
#define  offline_connectlog_device_info_sess_channel_type       (4)
	

#define  offline_connectlog_data_info_data_info_type            (0x1001C007)
#define  offline_connectlog_data_info_IPoffset_type             (0x1001C008)
#define  offline_connectlog_data_info_ethlength_type            (0x1001C009)
#define  offline_connectlog_data_info_llclength_type            (0x1001C00A)
#define  offline_connectlog_data_info_ethORllclength_type       (0x1001C00B)
#define  offline_connectlog_data_info_seq_no_type               (0x1001C00C)
#define  offline_connectlog_data_info_data_type                 (0x1001C00D)
#define  offline_connectlog_data_info_datasrc_type              (0x1001C00E)




#define OFFLINE_CONNECTLOG_IPHC_TYPE                            (0x10120001)
#define  offline_connectlog_iphc_cid_type                       (0x10120002)
#define  offline_connectlog_iphc_compralg_type                  (0x10120003)
#define  offline_connectlog_iphc_frame_type_type                (0x10120004)
#define  offline_connectlog_iphc_seq_num_type                   (0x10120005)


#define OFFLINE_CONNECTLOG_CISCO_PPP_TYPE                       (0x10121001)
#define  offline_connectlog_cisco_ppp_addr_type                 (0x10121002)
#define  offline_connectlog_cisco_ppp_control_type              (0x10121003)
#define  offline_connectlog_cisco_ppp_ether_type_type           (0x10121004)

#define OFFLINE_CONNECTLOG_PPP_TYPE                             (0x10122001)
#define  offline_connectlog_ppp_addr_type                       (0x10122002)
#define  offline_connectlog_ppp_control_type                    (0x10122003)
#define  offline_connectlog_ppp_proto_type                      (0x10122004)

#define OFFLINE_CONNECTLOG_FRAME_REALY_TYPE                     (0x10123001)
#define  offline_connectlog_frame_relay_addr_type               (0x10123002)
#define  offline_connectlog_frame_relay_control_type            (0x10123003)
#define  offline_connectlog_frame_relay_nlpid_type              (0x10123004)


#define OFFLINE_CONNECTLOG_X25_TYPE                             (0x10124001)
#define  offline_connectlog_x25_hdr_type                        (0x10124002)

#define OFFLINE_CONNECTLOG_DVBTS_TYPE                           (0x10125001)
#define  offline_connectlog_dvbts_pdumac_type                   (0x10125002)
#define  offline_connectlog_dvbts_mpe_hdr_type                  (0x10125003)
#define  offline_connectlog_dvbts_str_type_type                 (0x10125004)
#define  offline_connectlog_dvbts_str_mode_type                 (0x10125005)
#define  offline_connectlog_dvbts_isi_type                      (0x10125006)
#define  offline_connectlog_dvbts_pid_type                      (0x10125007)

#define OFFLINE_CONNECTLOG_DVBGS_TYPE                           (0x10126001)
#define  offline_connectlog_dvbgs_signal_type_type              (0x10126002)
#define  offline_connectlog_dvbgs_str_type_type                 (0x10126003)
#define  offline_connectlog_dvbgs_str_mode_type                 (0x10126004)
#define  offline_connectlog_dvbgs_str_id_type                   (0x10126005)

#define OFFLINE_CONNECTLOG_ETH_TYPE                             (0x10111001)
#define OFFLINE_CONNECTLOG_LLC_TYPE                             (0x10112001)
#define OFFLINE_CONNECTLOG_WAV_TYPE                             (0x1038C001)

#define OFFLINE_CONNECTLOG_SPPP_TYPE                            (0x110ba001)
#define  offline_connectlog_sppp_line_name_type                  (0x110ba002)
#define  offline_connectlog_sppp_line_dir_type                   (0x110ba003)
#define  offline_connectlog_sppp_line_bw_type                    (0x110ba004)
#define  offline_connectlog_sppp_load_type_type                  (0x110ba005)
#define  offline_connectlog_sppp_timestamp_type                  (0x110ba006)
#define  offline_connectlog_sppp_src_addr_type                   (0x110ba007)
#define  offline_connectlog_sppp_dst_addr_type                   (0x110ba008)

#define offline_pro_type_iphc           (208)
#define offline_pro_type_wav            (214)
#define offline_pro_type_switch_mc      (215)
#define offline_pro_type_cisco_ppp      (216)
#define offline_pro_type_ppp            (217)
#define offline_pro_type_frame_relay    (218)
#define offline_pro_type_x25            (219)
#define offline_pro_type_dvbgs          (220)
#define offline_pro_type_dvbts          (221)
#define offline_pro_type_sppp           (222)
#define offline_pro_type_atm            (223)
#define offline_pro_type_llc            (224)
#define offline_pro_type_eth            (225)
