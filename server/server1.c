#define _GNU_SOURCE
#include <link.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

void *tmp;

void take_data_pointers_backup(SSL_CTX *ctx)
{
	//Open File for backup
    FILE *fp;
    fp = fopen("d_backup","w");

    fwrite(ctx->method, 8, 1, fp);
	fwrite(ctx->cert_store, 144, 1, fp);
	fwrite(ctx->cert_store->objs, 26322896, 1, fp);
	fwrite(ctx->param, 56, 1, fp);
	fwrite(ctx->wbuf_freelist, 24, 1, fp);
	fwrite(ctx->rbuf_freelist, 24, 1, fp);
	
	//Close the file
	fclose(fp);
}

void take_function_pointers_backup(SSL_CTX *ctx) 
{
	//Open File for backup
    FILE *fp;
    fp = fopen("backup","w");
    
	if(ctx->method->ssl_new != 0) 
 	 fprintf(fp,"ssl_new %lx\n",(void*)ctx->method->ssl_new-tmp);
	else 
		 fprintf(fp,"ssl_new 0\n");
	if(ctx->method->ssl_clear != 0) 
		 fprintf(fp,"ssl_clear %lx\n",(void*)ctx->method->ssl_clear-tmp);
	else 
		 fprintf(fp,"ssl_clear 0\n");
	if(ctx->method->ssl_free != 0) 
		 fprintf(fp,"ssl_free %lx\n",(void*)ctx->method->ssl_free-tmp);
	else 
		 fprintf(fp,"ssl_free 0\n");
	if(ctx->method->ssl_accept != 0) 
		 fprintf(fp,"ssl_accept %lx\n",(void*)ctx->method->ssl_accept-tmp);
	else 
		 fprintf(fp,"ssl_accept 0\n");
	if(ctx->method->ssl_connect != 0) 
		 fprintf(fp,"ssl_connect %lx\n",(void*)ctx->method->ssl_connect-tmp);
	else 
		 fprintf(fp,"ssl_connect 0\n");
	if(ctx->method->ssl_read != 0) 
		 fprintf(fp,"ssl_read %lx\n",(void*)ctx->method->ssl_read-tmp);
	else 
		 fprintf(fp,"ssl_read 0\n");
	if(ctx->method->ssl_peek != 0) 
		 fprintf(fp,"ssl_peek %lx\n",(void*)ctx->method->ssl_peek-tmp);
	else 
		 fprintf(fp,"ssl_peek 0\n");
	if(ctx->method->ssl_write != 0) 
		 fprintf(fp,"ssl_write %lx\n",(void*)ctx->method->ssl_write-tmp);
	else 
		 fprintf(fp,"ssl_write 0\n");
	if(ctx->method->ssl_shutdown != 0) 
		 fprintf(fp,"ssl_shutdown %lx\n",(void*)ctx->method->ssl_shutdown-tmp);
	else 
		 fprintf(fp,"ssl_shutdown 0\n");
	if(ctx->method->ssl_renegotiate != 0) 
		 fprintf(fp,"ssl_renegotiate %lx\n",(void*)ctx->method->ssl_renegotiate-tmp);
	else 
		 fprintf(fp,"ssl_renegotiate 0\n");
	if(ctx->method->ssl_renegotiate_check != 0) 
		 fprintf(fp,"ssl_renegotiate_check %lx\n",(void*)ctx->method->ssl_renegotiate_check-tmp);
	else 
		 fprintf(fp,"ssl_renegotiate_check 0\n");
	if(ctx->method->ssl_get_message != 0) 
		 fprintf(fp,"ssl_get_message %lx\n",(void*)ctx->method->ssl_get_message-tmp);
	else 
		 fprintf(fp,"ssl_get_message 0\n");
	if(ctx->method->ssl_read_bytes != 0) 
		 fprintf(fp,"ssl_read_bytes %lx\n",(void*)ctx->method->ssl_read_bytes-tmp);
	else 
		 fprintf(fp,"ssl_read_bytes 0\n");
	if(ctx->method->ssl_write_bytes != 0) 
		 fprintf(fp,"ssl_write_bytes %lx\n",(void*)ctx->method->ssl_write_bytes-tmp);
	else 
		 fprintf(fp,"ssl_write_bytes 0\n");
	if(ctx->method->ssl_dispatch_alert != 0) 
		 fprintf(fp,"ssl_dispatch_alert %lx\n",(void*)ctx->method->ssl_dispatch_alert-tmp);
	else 
		 fprintf(fp,"ssl_dispatch_alert 0\n");
	if(ctx->method->ssl_ctrl != 0) 
		 fprintf(fp,"ssl_ctrl %lx\n",(void*)ctx->method->ssl_ctrl-tmp);
	else 
		 fprintf(fp,"ssl_ctrl 0\n");
	if(ctx->method->ssl_ctx_ctrl != 0) 
		 fprintf(fp,"ssl_ctx_ctrl %lx\n",(void*)ctx->method->ssl_ctx_ctrl-tmp);
	else 
		 fprintf(fp,"ssl_ctx_ctrl 0\n");
	if(ctx->method->get_cipher_by_char != 0) 
		 fprintf(fp,"get_cipher_by_char %lx\n",(void*)ctx->method->get_cipher_by_char-tmp);
	else 
		 fprintf(fp,"get_cipher_by_char 0\n");
	if(ctx->method->put_cipher_by_char != 0) 
		 fprintf(fp,"put_cipher_by_char %lx\n",(void*)ctx->method->put_cipher_by_char-tmp);
	else 
		 fprintf(fp,"put_cipher_by_char 0\n");
	if(ctx->method->ssl_pending != 0) 
		 fprintf(fp,"ssl_pending %lx\n",(void*)ctx->method->ssl_pending-tmp);
	else 
		 fprintf(fp,"ssl_pending 0\n");
	if(ctx->method->num_ciphers != 0) 
		 fprintf(fp,"num_ciphers %lx\n",(void*)ctx->method->num_ciphers-tmp);
	else 
		 fprintf(fp,"num_ciphers 0\n");
	if(ctx->method->get_cipher != 0) 
		 fprintf(fp,"get_cipher %lx\n",(void*)ctx->method->get_cipher-tmp);
	else 
		 fprintf(fp,"get_cipher 0\n");
	if(ctx->method->get_ssl_method != 0) 
		 fprintf(fp,"get_ssl_method %lx\n",(void*)ctx->method->get_ssl_method-tmp);
	else 
		 fprintf(fp,"get_ssl_method 0\n");
	if(ctx->method->get_timeout != 0) 
		 fprintf(fp,"get_timeout %lx\n",(void*)ctx->method->get_timeout-tmp);
	else 
		 fprintf(fp,"get_timeout 0\n");
	if(ctx->method->ssl_version != 0) 
		 fprintf(fp,"ssl_version %lx\n",(void*)ctx->method->ssl_version-tmp);
	else 
		 fprintf(fp,"ssl_version 0\n");
	if(ctx->method->ssl_callback_ctrl != 0) 
		 fprintf(fp,"ssl_callback_ctrl %lx\n",(void*)ctx->method->ssl_callback_ctrl-tmp);
	else 
		 fprintf(fp,"ssl_callback_ctrl 0\n");
	if(ctx->method->ssl_ctx_callback_ctrl != 0) 
		 fprintf(fp,"ssl_ctx_callback_ctrl %lx\n",(void*)ctx->method->ssl_ctx_callback_ctrl-tmp);
	else 
		 fprintf(fp,"ssl_ctx_callback_ctrl 0\n");
	if(ctx->cert_store->verify != 0) 
		 fprintf(fp,"verify %lx\n",(void*)ctx->cert_store->verify-tmp);
	else 
		 fprintf(fp,"verify 0\n");
	if(ctx->cert_store->verify_cb != 0) 
		 fprintf(fp,"verify_cb %lx\n",(void*)ctx->cert_store->verify_cb-tmp);
	else 
		 fprintf(fp,"verify_cb 0\n");
	if(ctx->cert_store->get_issuer != 0) 
		 fprintf(fp,"get_issuer %lx\n",(void*)ctx->cert_store->get_issuer-tmp);
	else 
		 fprintf(fp,"get_issuer 0\n");
	if(ctx->cert_store->check_issued != 0) 
		 fprintf(fp,"check_issued %lx\n",(void*)ctx->cert_store->check_issued-tmp);
	else 
		 fprintf(fp,"check_issued 0\n");
	if(ctx->cert_store->check_revocation != 0) 
		 fprintf(fp,"check_revocation %lx\n",(void*)ctx->cert_store->check_revocation-tmp);
	else 
		 fprintf(fp,"check_revocation 0\n");
	if(ctx->cert_store->get_crl != 0) 
		 fprintf(fp,"get_crl %lx\n",(void*)ctx->cert_store->get_crl-tmp);
	else 
		 fprintf(fp,"get_crl 0\n");
	if(ctx->cert_store->check_crl != 0) 
		 fprintf(fp,"check_crl %lx\n",(void*)ctx->cert_store->check_crl-tmp);
	else 
		 fprintf(fp,"check_crl 0\n");
	if(ctx->cert_store->cert_crl != 0) 
		 fprintf(fp,"cert_crl %lx\n",(void*)ctx->cert_store->cert_crl-tmp);
	else 
		 fprintf(fp,"cert_crl 0\n");
	if(ctx->cert_store->lookup_certs != 0) 
		 fprintf(fp,"lookup_certs %lx\n",(void*)ctx->cert_store->lookup_certs-tmp);
	else 
		 fprintf(fp,"lookup_certs 0\n");
	if(ctx->cert_store->lookup_crls != 0) 
		 fprintf(fp,"lookup_crls %lx\n",(void*)ctx->cert_store->lookup_crls-tmp);
	else 
		 fprintf(fp,"lookup_crls 0\n");
	if(ctx->cert_store->cleanup != 0) 
		 fprintf(fp,"cleanup %lx\n",(void*)ctx->cert_store->cleanup-tmp);
	else 
		 fprintf(fp,"cleanup 0\n");
	if(ctx->new_session_cb != 0) 
		 fprintf(fp,"new_session_cb %lx\n",(void*)ctx->new_session_cb-tmp);
	else 
		 fprintf(fp,"new_session_cb 0\n");
	if(ctx->remove_session_cb != 0) 
		 fprintf(fp,"remove_session_cb %lx\n",(void*)ctx->remove_session_cb-tmp);
	else 
		 fprintf(fp,"remove_session_cb 0\n");
	if(ctx->get_session_cb != 0) 
		 fprintf(fp,"get_session_cb %lx\n",(void*)ctx->get_session_cb-tmp);
	else 
		 fprintf(fp,"get_session_cb 0\n");
	if(ctx->app_verify_callback != 0) 
		 fprintf(fp,"app_verify_callback %lx\n",(void*)ctx->app_verify_callback-tmp);
	else 
		 fprintf(fp,"app_verify_callback 0\n");
	if(ctx->client_cert_cb != 0) 
		 fprintf(fp,"client_cert_cb %lx\n",(void*)ctx->client_cert_cb-tmp);
	else 
		 fprintf(fp,"client_cert_cb 0\n");
	if(ctx->app_gen_cookie_cb != 0) 
		 fprintf(fp,"app_gen_cookie_cb %lx\n",(void*)ctx->app_gen_cookie_cb-tmp);
	else 
		 fprintf(fp,"app_gen_cookie_cb 0\n");
	if(ctx->app_verify_cookie_cb != 0) 
		 fprintf(fp,"app_verify_cookie_cb %lx\n",(void*)ctx->app_verify_cookie_cb-tmp);
	else 
		 fprintf(fp,"app_verify_cookie_cb 0\n");
	if(ctx->rsa_md5->init != 0) 
		 fprintf(fp,"init %lx\n",(void*)ctx->rsa_md5->init-tmp);
	else 
		 fprintf(fp,"init 0\n");
	if(ctx->rsa_md5->update != 0) 
		 fprintf(fp,"update %lx\n",(void*)ctx->rsa_md5->update-tmp);
	else 
		 fprintf(fp,"update 0\n");
	if(ctx->rsa_md5->final != 0) 
		 fprintf(fp,"final %lx\n",(void*)ctx->rsa_md5->final-tmp);
	else 
		 fprintf(fp,"final 0\n");
	if(ctx->rsa_md5->copy != 0) 
		 fprintf(fp,"copy %lx\n",(void*)ctx->rsa_md5->copy-tmp);
	else 
		 fprintf(fp,"copy 0\n");
	if(ctx->rsa_md5->cleanup != 0) 
		 fprintf(fp,"cleanup %lx\n",(void*)ctx->rsa_md5->cleanup-tmp);
	else 
		 fprintf(fp,"cleanup 0\n");
	if(ctx->rsa_md5->sign != 0) 
		 fprintf(fp,"sign %lx\n",(void*)ctx->rsa_md5->sign-tmp);
	else 
		 fprintf(fp,"sign 0\n");
	if(ctx->rsa_md5->verify != 0) 
		 fprintf(fp,"verify %lx\n",(void*)ctx->rsa_md5->verify-tmp);
	else 
		 fprintf(fp,"verify 0\n");
	if(ctx->rsa_md5->md_ctrl != 0) 
		 fprintf(fp,"md_ctrl %lx\n",(void*)ctx->rsa_md5->md_ctrl-tmp);
	else 
		 fprintf(fp,"md_ctrl 0\n");
	if(ctx->md5->init != 0) 
		 fprintf(fp,"init %lx\n",(void*)ctx->md5->init-tmp);
	else 
		 fprintf(fp,"init 0\n");
	if(ctx->md5->update != 0) 
		 fprintf(fp,"update %lx\n",(void*)ctx->md5->update-tmp);
	else 
		 fprintf(fp,"update 0\n");
	if(ctx->md5->final != 0) 
		 fprintf(fp,"final %lx\n",(void*)ctx->md5->final-tmp);
	else 
		 fprintf(fp,"final 0\n");
	if(ctx->md5->copy != 0) 
		 fprintf(fp,"copy %lx\n",(void*)ctx->md5->copy-tmp);
	else 
		 fprintf(fp,"copy 0\n");
	if(ctx->md5->cleanup != 0) 
		 fprintf(fp,"cleanup %lx\n",(void*)ctx->md5->cleanup-tmp);
	else 
		 fprintf(fp,"cleanup 0\n");
	if(ctx->md5->sign != 0) 
		 fprintf(fp,"sign %lx\n",(void*)ctx->md5->sign-tmp);
	else 
		 fprintf(fp,"sign 0\n");
	if(ctx->md5->verify != 0) 
		 fprintf(fp,"verify %lx\n",(void*)ctx->md5->verify-tmp);
	else 
		 fprintf(fp,"verify 0\n");
	if(ctx->md5->md_ctrl != 0) 
		 fprintf(fp,"md_ctrl %lx\n",(void*)ctx->md5->md_ctrl-tmp);
	else 
		 fprintf(fp,"md_ctrl 0\n");
	if(ctx->sha1->init != 0) 
		 fprintf(fp,"init %lx\n",(void*)ctx->sha1->init-tmp);
	else 
		 fprintf(fp,"init 0\n");
	if(ctx->sha1->update != 0) 
		 fprintf(fp,"update %lx\n",(void*)ctx->sha1->update-tmp);
	else 
		 fprintf(fp,"update 0\n");
	if(ctx->sha1->final != 0) 
		 fprintf(fp,"final %lx\n",(void*)ctx->sha1->final-tmp);
	else 
		 fprintf(fp,"final 0\n");
	if(ctx->sha1->copy != 0) 
		 fprintf(fp,"copy %lx\n",(void*)ctx->sha1->copy-tmp);
	else 
		 fprintf(fp,"copy 0\n");
	if(ctx->sha1->cleanup != 0) 
		 fprintf(fp,"cleanup %lx\n",(void*)ctx->sha1->cleanup-tmp);
	else 
		 fprintf(fp,"cleanup 0\n");
	if(ctx->sha1->sign != 0) 
		 fprintf(fp,"sign %lx\n",(void*)ctx->sha1->sign-tmp);
	else 
		 fprintf(fp,"sign 0\n");
	if(ctx->sha1->verify != 0) 
		 fprintf(fp,"verify %lx\n",(void*)ctx->sha1->verify-tmp);
	else 
		 fprintf(fp,"verify 0\n");
	if(ctx->sha1->md_ctrl != 0) 
		 fprintf(fp,"md_ctrl %lx\n",(void*)ctx->sha1->md_ctrl-tmp);
	else 
		 fprintf(fp,"md_ctrl 0\n");
	if(ctx->info_callback != 0) 
		 fprintf(fp,"info_callback %lx\n",(void*)ctx->info_callback-tmp);
	else 
		 fprintf(fp,"info_callback 0\n");
	if(ctx->msg_callback != 0) 
		 fprintf(fp,"msg_callback %lx\n",(void*)ctx->msg_callback-tmp);
	else 
		 fprintf(fp,"msg_callback 0\n");
	if(ctx->default_verify_callback != 0) 
		 fprintf(fp,"default_verify_callback %lx\n",(void*)ctx->default_verify_callback-tmp);
	else 
		 fprintf(fp,"default_verify_callback 0\n");
	if(ctx->tlsext_servername_callback != 0) 
		 fprintf(fp,"tlsext_servername_callback %lx\n",(void*)ctx->tlsext_servername_callback-tmp);
	else 
		 fprintf(fp,"tlsext_servername_callback 0\n");
	if(ctx->tlsext_ticket_key_cb != 0) 
		 fprintf(fp,"tlsext_ticket_key_cb %lx\n",(void*)ctx->tlsext_ticket_key_cb-tmp);
	else 
		 fprintf(fp,"tlsext_ticket_key_cb 0\n");
	if(ctx->tlsext_status_cb != 0) 
		 fprintf(fp,"tlsext_status_cb %lx\n",(void*)ctx->tlsext_status_cb-tmp);
	else 
		 fprintf(fp,"tlsext_status_cb 0\n");
	if(ctx->tlsext_opaque_prf_input_callback != 0) 
		 fprintf(fp,"tlsext_opaque_prf_input_callback %lx\n",(void*)ctx->tlsext_opaque_prf_input_callback-tmp);
	else 
		 fprintf(fp,"tlsext_opaque_prf_input_callback 0\n");
	if(ctx->psk_client_callback != 0) 
		 fprintf(fp,"psk_client_callback %lx\n",(void*)ctx->psk_client_callback-tmp);
	else 
		 fprintf(fp,"psk_client_callback 0\n");
	if(ctx->psk_server_callback != 0) 
		 fprintf(fp,"psk_server_callback %lx\n",(void*)ctx->psk_server_callback-tmp);
	else 
		 fprintf(fp,"psk_server_callback 0\n");
	/*if(ctx->srp_ctx->TLS_ext_srp_username_callback != 0) 
		 fprintf(fp,"TLS_ext_srp_username_callback %lx\n",(void*)ctx->srp_ctx->TLS_ext_srp_username_callback-tmp);
	else 
		 fprintf(fp,"TLS_ext_srp_username_callback 0\n");
	if(ctx->srp_ctx->SRP_verify_param_callback != 0) 
		 fprintf(fp,"SRP_verify_param_callback %lx\n",(void*)ctx->srp_ctx->SRP_verify_param_callback-tmp);
	else 
		 fprintf(fp,"SRP_verify_param_callback 0\n");
	if(ctx->srp_ctx->SRP_give_srp_client_pwd_callback != 0) 
		 fprintf(fp,"SRP_give_srp_client_pwd_callback %lx\n",(void*)ctx->srp_ctx->SRP_give_srp_client_pwd_callback-tmp);
	else 
		 fprintf(fp,"SRP_give_srp_client_pwd_callback 0\n");*/
	if(ctx->next_protos_advertised_cb != 0) 
		 fprintf(fp,"next_protos_advertised_cb %lx\n",(void*)ctx->next_protos_advertised_cb-tmp);
	else 
		 fprintf(fp,"next_protos_advertised_cb 0\n");
	if(ctx->next_proto_select_cb != 0) 
		 fprintf(fp,"next_proto_select_cb %lx\n",(void*)ctx->next_proto_select_cb-tmp);
	else 
		 fprintf(fp,"next_proto_select_cb 0\n");

	/*if(ctx->client_cert_engine->rsa_meth->rsa_pub_enc != 0) 
		 fprintf(fp,"rsa_pub_enc %lx\n",(void*)ctx->client_cert_engine->rsa_meth->rsa_pub_enc-tmp);
	else 
		 fprintf(fp,"rsa_pub_enc 0\n");
	if(ctx->client_cert_engine->rsa_meth->rsa_pub_dec != 0) 
		 fprintf(fp,"rsa_pub_dec %lx\n",(void*)ctx->client_cert_engine->rsa_meth->rsa_pub_dec-tmp);
	else 
		 fprintf(fp,"rsa_pub_dec 0\n");
	if(ctx->client_cert_engine->rsa_meth->rsa_priv_enc != 0) 
		 fprintf(fp,"rsa_priv_enc %lx\n",(void*)ctx->client_cert_engine->rsa_meth->rsa_priv_enc-tmp);
	else 
		 fprintf(fp,"rsa_priv_enc 0\n");
	if(ctx->client_cert_engine->rsa_meth->rsa_priv_dec != 0) 
		 fprintf(fp,"rsa_priv_dec %lx\n",(void*)ctx->client_cert_engine->rsa_meth->rsa_priv_dec-tmp);
	else 
		 fprintf(fp,"rsa_priv_dec 0\n");
	if(ctx->client_cert_engine->rsa_meth->rsa_mod_exp != 0) 
		 fprintf(fp,"rsa_mod_exp %lx\n",(void*)ctx->client_cert_engine->rsa_meth->rsa_mod_exp-tmp);
	else 
		 fprintf(fp,"rsa_mod_exp 0\n");
	if(ctx->client_cert_engine->rsa_meth->bn_mod_exp != 0) 
		 fprintf(fp,"bn_mod_exp %lx\n",(void*)ctx->client_cert_engine->rsa_meth->bn_mod_exp-tmp);
	else 
		 fprintf(fp,"bn_mod_exp 0\n");
	if(ctx->client_cert_engine->rsa_meth->init != 0) 
		 fprintf(fp,"init %lx\n",(void*)ctx->client_cert_engine->rsa_meth->init-tmp);
	else 
		 fprintf(fp,"init 0\n");
	if(ctx->client_cert_engine->rsa_meth->finish != 0) 
		 fprintf(fp,"finish %lx\n",(void*)ctx->client_cert_engine->rsa_meth->finish-tmp);
	else 
		 fprintf(fp,"finish 0\n");
	if(ctx->client_cert_engine->rsa_meth->rsa_sign != 0) 
		 fprintf(fp,"rsa_sign %lx\n",(void*)ctx->client_cert_engine->rsa_meth->rsa_sign-tmp);
	else 
		 fprintf(fp,"rsa_sign 0\n");
	if(ctx->client_cert_engine->rsa_meth->rsa_verify != 0) 
		 fprintf(fp,"rsa_verify %lx\n",(void*)ctx->client_cert_engine->rsa_meth->rsa_verify-tmp);
	else 
		 fprintf(fp,"rsa_verify 0\n");
	if(ctx->client_cert_engine->rsa_meth->rsa_keygen != 0) 
		 fprintf(fp,"rsa_keygen %lx\n",(void*)ctx->client_cert_engine->rsa_meth->rsa_keygen-tmp);
	else 
		 fprintf(fp,"rsa_keygen 0\n");

	if(ctx->client_cert_engine->dsa_meth->dsa_do_sign != 0) 
		 fprintf(fp,"dsa_do_sign %lx\n",(void*)ctx->client_cert_engine->dsa_meth->dsa_do_sign-tmp);
	else 
		 fprintf(fp,"dsa_do_sign 0\n");
	if(ctx->client_cert_engine->dsa_meth->dsa_sign_setup != 0) 
		 fprintf(fp,"dsa_sign_setup %lx\n",(void*)ctx->client_cert_engine->dsa_meth->dsa_sign_setup-tmp);
	else 
		 fprintf(fp,"dsa_sign_setup 0\n");
	if(ctx->client_cert_engine->dsa_meth->dsa_do_verify != 0) 
		 fprintf(fp,"dsa_do_verify %lx\n",(void*)ctx->client_cert_engine->dsa_meth->dsa_do_verify-tmp);
	else 
		 fprintf(fp,"dsa_do_verify 0\n");
	if(ctx->client_cert_engine->dsa_meth->dsa_mod_exp != 0) 
		 fprintf(fp,"dsa_mod_exp %lx\n",(void*)ctx->client_cert_engine->dsa_meth->dsa_mod_exp-tmp);
	else 
		 fprintf(fp,"dsa_mod_exp 0\n");
	if(ctx->client_cert_engine->dsa_meth->bn_mod_exp != 0) 
		 fprintf(fp,"bn_mod_exp %lx\n",(void*)ctx->client_cert_engine->dsa_meth->bn_mod_exp-tmp);
	else 
		 fprintf(fp,"bn_mod_exp 0\n");
	if(ctx->client_cert_engine->dsa_meth->init != 0) 
		 fprintf(fp,"init %lx\n",(void*)ctx->client_cert_engine->dsa_meth->init-tmp);
	else 
		 fprintf(fp,"init 0\n");
	if(ctx->client_cert_engine->dsa_meth->finish != 0) 
		 fprintf(fp,"finish %lx\n",(void*)ctx->client_cert_engine->dsa_meth->finish-tmp);
	else 
		 fprintf(fp,"finish 0\n");
	if(ctx->client_cert_engine->dsa_meth->dsa_paramgen != 0) 
		 fprintf(fp,"dsa_paramgen %lx\n",(void*)ctx->client_cert_engine->dsa_meth->dsa_paramgen-tmp);
	else 
		 fprintf(fp,"dsa_paramgen 0\n");
	if(ctx->client_cert_engine->dsa_meth->dsa_keygen != 0) 
		 fprintf(fp,"dsa_keygen %lx\n",(void*)ctx->client_cert_engine->dsa_meth->dsa_keygen-tmp);
	else 
		 fprintf(fp,"dsa_keygen 0\n");

	if(ctx->client_cert_engine->dh_meth->generate_key != 0) 
		 fprintf(fp,"generate_key %lx\n",(void*)ctx->client_cert_engine->dh_meth->generate_key-tmp);
	else 
		 fprintf(fp,"generate_key 0\n");
	if(ctx->client_cert_engine->dh_meth->compute_key != 0) 
		 fprintf(fp,"compute_key %lx\n",(void*)ctx->client_cert_engine->dh_meth->compute_key-tmp);
	else 
		 fprintf(fp,"compute_key 0\n");
	if(ctx->client_cert_engine->dh_meth->bn_mod_exp != 0) 
		 fprintf(fp,"bn_mod_exp %lx\n",(void*)ctx->client_cert_engine->dh_meth->bn_mod_exp-tmp);
	else 
		 fprintf(fp,"bn_mod_exp 0\n");
	if(ctx->client_cert_engine->dh_meth->init != 0) 
		 fprintf(fp,"init %lx\n",(void*)ctx->client_cert_engine->dh_meth->init-tmp);
	else 
		 fprintf(fp,"init 0\n");
	if(ctx->client_cert_engine->dh_meth->finish != 0) 
		 fprintf(fp,"finish %lx\n",(void*)ctx->client_cert_engine->dh_meth->finish-tmp);
	else 
		 fprintf(fp,"finish 0\n");
	if(ctx->client_cert_engine->dh_meth->generate_params != 0) 
		 fprintf(fp,"generate_params %lx\n",(void*)ctx->client_cert_engine->dh_meth->generate_params-tmp);
	else 
		 fprintf(fp,"generate_params 0\n");

	if(ctx->client_cert_engine->ecdh_meth->compute_key != 0) 
		 fprintf(fp,"compute_key %lx\n",(void*)ctx->client_cert_engine->ecdh_meth->compute_key-tmp);
	else 
		 fprintf(fp,"compute_key 0\n");
	if(ctx->client_cert_engine->ecdh_meth->init != 0) 
		 fprintf(fp,"init %lx\n",(void*)ctx->client_cert_engine->ecdh_meth->init-tmp);
	else 
		 fprintf(fp,"init 0\n");
	if(ctx->client_cert_engine->ecdh_meth->finish != 0) 
		 fprintf(fp,"finish %lx\n",(void*)ctx->client_cert_engine->ecdh_meth->finish-tmp);
	else 
		 fprintf(fp,"finish 0\n");

	if(ctx->client_cert_engine->ecdsa_meth->ecdsa_do_sign != 0) 
		 fprintf(fp,"ecdsa_do_sign %lx\n",(void*)ctx->client_cert_engine->ecdsa_meth->ecdsa_do_sign-tmp);
	else 
		 fprintf(fp,"ecdsa_do_sign 0\n");
	if(ctx->client_cert_engine->ecdsa_meth->ecdsa_sign_setup != 0) 
		 fprintf(fp,"ecdsa_sign_setup %lx\n",(void*)ctx->client_cert_engine->ecdsa_meth->ecdsa_sign_setup-tmp);
	else 
		 fprintf(fp,"ecdsa_sign_setup 0\n");
	if(ctx->client_cert_engine->ecdsa_meth->ecdsa_do_verify != 0) 
		 fprintf(fp,"ecdsa_do_verify %lx\n",(void*)ctx->client_cert_engine->ecdsa_meth->ecdsa_do_verify-tmp);
	else 
		 fprintf(fp,"ecdsa_do_verify 0\n");
	if(ctx->client_cert_engine->ecdsa_meth->init != 0) 
		 fprintf(fp,"init %lx\n",(void*)ctx->client_cert_engine->ecdsa_meth->init-tmp);
	else 
		 fprintf(fp,"init 0\n");
	if(ctx->client_cert_engine->ecdsa_meth->finish != 0) 
		 fprintf(fp,"finish %lx\n",(void*)ctx->client_cert_engine->ecdsa_meth->finish-tmp);
	else 
		 fprintf(fp,"finish 0\n");

	if(ctx->client_cert_engine->rand_meth->seed != 0) 
		 fprintf(fp,"seed %lx\n",(void*)ctx->client_cert_engine->rand_meth->seed-tmp);
	else 
		 fprintf(fp,"seed 0\n");
	if(ctx->client_cert_engine->rand_meth->bytes != 0) 
		 fprintf(fp,"bytes %lx\n",(void*)ctx->client_cert_engine->rand_meth->bytes-tmp);
	else 
		 fprintf(fp,"bytes 0\n");
	if(ctx->client_cert_engine->rand_meth->cleanup != 0) 
		 fprintf(fp,"cleanup %lx\n",(void*)ctx->client_cert_engine->rand_meth->cleanup-tmp);
	else 
		 fprintf(fp,"cleanup 0\n");
	if(ctx->client_cert_engine->rand_meth->add != 0) 
		 fprintf(fp,"add %lx\n",(void*)ctx->client_cert_engine->rand_meth->add-tmp);
	else 
		 fprintf(fp,"add 0\n");
	if(ctx->client_cert_engine->rand_meth->pseudorand != 0) 
		 fprintf(fp,"pseudorand %lx\n",(void*)ctx->client_cert_engine->rand_meth->pseudorand-tmp);
	else 
		 fprintf(fp,"pseudorand 0\n");
	if(ctx->client_cert_engine->rand_meth->status != 0) 
		 fprintf(fp,"status %lx\n",(void*)ctx->client_cert_engine->rand_meth->status-tmp);
	else 
		 fprintf(fp,"status 0\n");


	if(ctx->client_cert_engine->prev->rsa_meth->rsa_pub_enc != 0) 
		 fprintf(fp,"rsa_pub_enc %lx\n",(void*)ctx->client_cert_engine->prev->rsa_meth->rsa_pub_enc-tmp);
	else 
		 fprintf(fp,"rsa_pub_enc 0\n");
	if(ctx->client_cert_engine->prev->rsa_meth->rsa_pub_dec != 0) 
		 fprintf(fp,"rsa_pub_dec %lx\n",(void*)ctx->client_cert_engine->prev->rsa_meth->rsa_pub_dec-tmp);
	else 
		 fprintf(fp,"rsa_pub_dec 0\n");
	if(ctx->client_cert_engine->prev->rsa_meth->rsa_priv_enc != 0) 
		 fprintf(fp,"rsa_priv_enc %lx\n",(void*)ctx->client_cert_engine->prev->rsa_meth->rsa_priv_enc-tmp);
	else 
		 fprintf(fp,"rsa_priv_enc 0\n");
	if(ctx->client_cert_engine->prev->rsa_meth->rsa_priv_dec != 0) 
		 fprintf(fp,"rsa_priv_dec %lx\n",(void*)ctx->client_cert_engine->prev->rsa_meth->rsa_priv_dec-tmp);
	else 
		 fprintf(fp,"rsa_priv_dec 0\n");
	if(ctx->client_cert_engine->prev->rsa_meth->rsa_mod_exp != 0) 
		 fprintf(fp,"rsa_mod_exp %lx\n",(void*)ctx->client_cert_engine->prev->rsa_meth->rsa_mod_exp-tmp);
	else 
		 fprintf(fp,"rsa_mod_exp 0\n");
	if(ctx->client_cert_engine->prev->rsa_meth->bn_mod_exp != 0) 
		 fprintf(fp,"bn_mod_exp %lx\n",(void*)ctx->client_cert_engine->prev->rsa_meth->bn_mod_exp-tmp);
	else 
		 fprintf(fp,"bn_mod_exp 0\n");
	if(ctx->client_cert_engine->prev->rsa_meth->init != 0) 
		 fprintf(fp,"init %lx\n",(void*)ctx->client_cert_engine->prev->rsa_meth->init-tmp);
	else 
		 fprintf(fp,"init 0\n");
	if(ctx->client_cert_engine->prev->rsa_meth->finish != 0) 
		 fprintf(fp,"finish %lx\n",(void*)ctx->client_cert_engine->prev->rsa_meth->finish-tmp);
	else 
		 fprintf(fp,"finish 0\n");
	if(ctx->client_cert_engine->prev->rsa_meth->rsa_sign != 0) 
		 fprintf(fp,"rsa_sign %lx\n",(void*)ctx->client_cert_engine->prev->rsa_meth->rsa_sign-tmp);
	else 
		 fprintf(fp,"rsa_sign 0\n");
	if(ctx->client_cert_engine->prev->rsa_meth->rsa_verify != 0) 
		 fprintf(fp,"rsa_verify %lx\n",(void*)ctx->client_cert_engine->prev->rsa_meth->rsa_verify-tmp);
	else 
		 fprintf(fp,"rsa_verify 0\n");
	if(ctx->client_cert_engine->prev->rsa_meth->rsa_keygen != 0) 
		 fprintf(fp,"rsa_keygen %lx\n",(void*)ctx->client_cert_engine->prev->rsa_meth->rsa_keygen-tmp);
	else 
		 fprintf(fp,"rsa_keygen 0\n");

	if(ctx->client_cert_engine->prev->dsa_meth->dsa_do_sign != 0) 
		 fprintf(fp,"dsa_do_sign %lx\n",(void*)ctx->client_cert_engine->prev->dsa_meth->dsa_do_sign-tmp);
	else 
		 fprintf(fp,"dsa_do_sign 0\n");
	if(ctx->client_cert_engine->prev->dsa_meth->dsa_sign_setup != 0) 
		 fprintf(fp,"dsa_sign_setup %lx\n",(void*)ctx->client_cert_engine->prev->dsa_meth->dsa_sign_setup-tmp);
	else 
		 fprintf(fp,"dsa_sign_setup 0\n");
	if(ctx->client_cert_engine->prev->dsa_meth->dsa_do_verify != 0) 
		 fprintf(fp,"dsa_do_verify %lx\n",(void*)ctx->client_cert_engine->prev->dsa_meth->dsa_do_verify-tmp);
	else 
		 fprintf(fp,"dsa_do_verify 0\n");
	if(ctx->client_cert_engine->prev->dsa_meth->dsa_mod_exp != 0) 
		 fprintf(fp,"dsa_mod_exp %lx\n",(void*)ctx->client_cert_engine->prev->dsa_meth->dsa_mod_exp-tmp);
	else 
		 fprintf(fp,"dsa_mod_exp 0\n");
	if(ctx->client_cert_engine->prev->dsa_meth->bn_mod_exp != 0) 
		 fprintf(fp,"bn_mod_exp %lx\n",(void*)ctx->client_cert_engine->prev->dsa_meth->bn_mod_exp-tmp);
	else 
		 fprintf(fp,"bn_mod_exp 0\n");
	if(ctx->client_cert_engine->prev->dsa_meth->init != 0) 
		 fprintf(fp,"init %lx\n",(void*)ctx->client_cert_engine->prev->dsa_meth->init-tmp);
	else 
		 fprintf(fp,"init 0\n");
	if(ctx->client_cert_engine->prev->dsa_meth->finish != 0) 
		 fprintf(fp,"finish %lx\n",(void*)ctx->client_cert_engine->prev->dsa_meth->finish-tmp);
	else 
		 fprintf(fp,"finish 0\n");
	if(ctx->client_cert_engine->prev->dsa_meth->dsa_paramgen != 0) 
		 fprintf(fp,"dsa_paramgen %lx\n",(void*)ctx->client_cert_engine->prev->dsa_meth->dsa_paramgen-tmp);
	else 
		 fprintf(fp,"dsa_paramgen 0\n");
	if(ctx->client_cert_engine->prev->dsa_meth->dsa_keygen != 0) 
		 fprintf(fp,"dsa_keygen %lx\n",(void*)ctx->client_cert_engine->prev->dsa_meth->dsa_keygen-tmp);
	else 
		 fprintf(fp,"dsa_keygen 0\n");

	if(ctx->client_cert_engine->prev->dh_meth->generate_key != 0) 
		 fprintf(fp,"generate_key %lx\n",(void*)ctx->client_cert_engine->prev->dh_meth->generate_key-tmp);
	else 
		 fprintf(fp,"generate_key 0\n");
	if(ctx->client_cert_engine->prev->dh_meth->compute_key != 0) 
		 fprintf(fp,"compute_key %lx\n",(void*)ctx->client_cert_engine->prev->dh_meth->compute_key-tmp);
	else 
		 fprintf(fp,"compute_key 0\n");
	if(ctx->client_cert_engine->prev->dh_meth->bn_mod_exp != 0) 
		 fprintf(fp,"bn_mod_exp %lx\n",(void*)ctx->client_cert_engine->prev->dh_meth->bn_mod_exp-tmp);
	else 
		 fprintf(fp,"bn_mod_exp 0\n");
	if(ctx->client_cert_engine->prev->dh_meth->init != 0) 
		 fprintf(fp,"init %lx\n",(void*)ctx->client_cert_engine->prev->dh_meth->init-tmp);
	else 
		 fprintf(fp,"init 0\n");
	if(ctx->client_cert_engine->prev->dh_meth->finish != 0) 
		 fprintf(fp,"finish %lx\n",(void*)ctx->client_cert_engine->prev->dh_meth->finish-tmp);
	else 
		 fprintf(fp,"finish 0\n");
	if(ctx->client_cert_engine->prev->dh_meth->generate_params != 0) 
		 fprintf(fp,"generate_params %lx\n",(void*)ctx->client_cert_engine->prev->dh_meth->generate_params-tmp);
	else 
		 fprintf(fp,"generate_params 0\n");

	if(ctx->client_cert_engine->prev->ecdh_meth->compute_key != 0) 
		 fprintf(fp,"compute_key %lx\n",(void*)ctx->client_cert_engine->prev->ecdh_meth->compute_key-tmp);
	else 
		 fprintf(fp,"compute_key 0\n");
	if(ctx->client_cert_engine->prev->ecdh_meth->init != 0) 
		 fprintf(fp,"init %lx\n",(void*)ctx->client_cert_engine->prev->ecdh_meth->init-tmp);
	else 
		 fprintf(fp,"init 0\n");
	if(ctx->client_cert_engine->prev->ecdh_meth->finish != 0) 
		 fprintf(fp,"finish %lx\n",(void*)ctx->client_cert_engine->prev->ecdh_meth->finish-tmp);
	else 
		 fprintf(fp,"finish 0\n");

	if(ctx->client_cert_engine->prev->ecdsa_meth->ecdsa_do_sign != 0) 
		 fprintf(fp,"ecdsa_do_sign %lx\n",(void*)ctx->client_cert_engine->prev->ecdsa_meth->ecdsa_do_sign-tmp);
	else 
		 fprintf(fp,"ecdsa_do_sign 0\n");
	if(ctx->client_cert_engine->prev->ecdsa_meth->ecdsa_sign_setup != 0) 
		 fprintf(fp,"ecdsa_sign_setup %lx\n",(void*)ctx->client_cert_engine->prev->ecdsa_meth->ecdsa_sign_setup-tmp);
	else 
		 fprintf(fp,"ecdsa_sign_setup 0\n");
	if(ctx->client_cert_engine->prev->ecdsa_meth->ecdsa_do_verify != 0) 
		 fprintf(fp,"ecdsa_do_verify %lx\n",(void*)ctx->client_cert_engine->prev->ecdsa_meth->ecdsa_do_verify-tmp);
	else 
		 fprintf(fp,"ecdsa_do_verify 0\n");
	if(ctx->client_cert_engine->prev->ecdsa_meth->init != 0) 
		 fprintf(fp,"init %lx\n",(void*)ctx->client_cert_engine->prev->ecdsa_meth->init-tmp);
	else 
		 fprintf(fp,"init 0\n");
	if(ctx->client_cert_engine->prev->ecdsa_meth->finish != 0) 
		 fprintf(fp,"finish %lx\n",(void*)ctx->client_cert_engine->prev->ecdsa_meth->finish-tmp);
	else 
		 fprintf(fp,"finish 0\n");

	if(ctx->client_cert_engine->prev->rand_meth->seed != 0) 
		 fprintf(fp,"seed %lx\n",(void*)ctx->client_cert_engine->prev->rand_meth->seed-tmp);
	else 
		 fprintf(fp,"seed 0\n");
	if(ctx->client_cert_engine->prev->rand_meth->bytes != 0) 
		 fprintf(fp,"bytes %lx\n",(void*)ctx->client_cert_engine->prev->rand_meth->bytes-tmp);
	else 
		 fprintf(fp,"bytes 0\n");
	if(ctx->client_cert_engine->prev->rand_meth->cleanup != 0) 
		 fprintf(fp,"cleanup %lx\n",(void*)ctx->client_cert_engine->prev->rand_meth->cleanup-tmp);
	else 
		 fprintf(fp,"cleanup 0\n");
	if(ctx->client_cert_engine->prev->rand_meth->add != 0) 
		 fprintf(fp,"add %lx\n",(void*)ctx->client_cert_engine->prev->rand_meth->add-tmp);
	else 
		 fprintf(fp,"add 0\n");
	if(ctx->client_cert_engine->prev->rand_meth->pseudorand != 0) 
		 fprintf(fp,"pseudorand %lx\n",(void*)ctx->client_cert_engine->prev->rand_meth->pseudorand-tmp);
	else 
		 fprintf(fp,"pseudorand 0\n");
	if(ctx->client_cert_engine->prev->rand_meth->status != 0) 
		 fprintf(fp,"status %lx\n",(void*)ctx->client_cert_engine->prev->rand_meth->status-tmp);
	else 
		 fprintf(fp,"status 0\n");


	if(ctx->client_cert_engine->prev->rsa_meth->rsa_pub_enc != 0) 
		 fprintf(fp,"rsa_pub_enc %lx\n",(void*)ctx->client_cert_engine->prev->rsa_meth->rsa_pub_enc-tmp);
	else 
		 fprintf(fp,"rsa_pub_enc 0\n");
	if(ctx->client_cert_engine->prev->rsa_meth->rsa_pub_dec != 0) 
		 fprintf(fp,"rsa_pub_dec %lx\n",(void*)ctx->client_cert_engine->prev->rsa_meth->rsa_pub_dec-tmp);
	else 
		 fprintf(fp,"rsa_pub_dec 0\n");
	if(ctx->client_cert_engine->prev->rsa_meth->rsa_priv_enc != 0) 
		 fprintf(fp,"rsa_priv_enc %lx\n",(void*)ctx->client_cert_engine->prev->rsa_meth->rsa_priv_enc-tmp);
	else 
		 fprintf(fp,"rsa_priv_enc 0\n");
	if(ctx->client_cert_engine->prev->rsa_meth->rsa_priv_dec != 0) 
		 fprintf(fp,"rsa_priv_dec %lx\n",(void*)ctx->client_cert_engine->prev->rsa_meth->rsa_priv_dec-tmp);
	else 
		 fprintf(fp,"rsa_priv_dec 0\n");
	if(ctx->client_cert_engine->prev->rsa_meth->rsa_mod_exp != 0) 
		 fprintf(fp,"rsa_mod_exp %lx\n",(void*)ctx->client_cert_engine->prev->rsa_meth->rsa_mod_exp-tmp);
	else 
		 fprintf(fp,"rsa_mod_exp 0\n");
	if(ctx->client_cert_engine->prev->rsa_meth->bn_mod_exp != 0) 
		 fprintf(fp,"bn_mod_exp %lx\n",(void*)ctx->client_cert_engine->prev->rsa_meth->bn_mod_exp-tmp);
	else 
		 fprintf(fp,"bn_mod_exp 0\n");
	if(ctx->client_cert_engine->prev->rsa_meth->init != 0) 
		 fprintf(fp,"init %lx\n",(void*)ctx->client_cert_engine->prev->rsa_meth->init-tmp);
	else 
		 fprintf(fp,"init 0\n");
	if(ctx->client_cert_engine->prev->rsa_meth->finish != 0) 
		 fprintf(fp,"finish %lx\n",(void*)ctx->client_cert_engine->prev->rsa_meth->finish-tmp);
	else 
		 fprintf(fp,"finish 0\n");
	if(ctx->client_cert_engine->prev->rsa_meth->rsa_sign != 0) 
		 fprintf(fp,"rsa_sign %lx\n",(void*)ctx->client_cert_engine->prev->rsa_meth->rsa_sign-tmp);
	else 
		 fprintf(fp,"rsa_sign 0\n");
	if(ctx->client_cert_engine->prev->rsa_meth->rsa_verify != 0) 
		 fprintf(fp,"rsa_verify %lx\n",(void*)ctx->client_cert_engine->prev->rsa_meth->rsa_verify-tmp);
	else 
		 fprintf(fp,"rsa_verify 0\n");
	if(ctx->client_cert_engine->prev->rsa_meth->rsa_keygen != 0) 
		 fprintf(fp,"rsa_keygen %lx\n",(void*)ctx->client_cert_engine->prev->rsa_meth->rsa_keygen-tmp);
	else 
		 fprintf(fp,"rsa_keygen 0\n");

	if(ctx->client_cert_engine->prev->dsa_meth->dsa_do_sign != 0) 
		 fprintf(fp,"dsa_do_sign %lx\n",(void*)ctx->client_cert_engine->prev->dsa_meth->dsa_do_sign-tmp);
	else 
		 fprintf(fp,"dsa_do_sign 0\n");
	if(ctx->client_cert_engine->prev->dsa_meth->dsa_sign_setup != 0) 
		 fprintf(fp,"dsa_sign_setup %lx\n",(void*)ctx->client_cert_engine->prev->dsa_meth->dsa_sign_setup-tmp);
	else 
		 fprintf(fp,"dsa_sign_setup 0\n");
	if(ctx->client_cert_engine->prev->dsa_meth->dsa_do_verify != 0) 
		 fprintf(fp,"dsa_do_verify %lx\n",(void*)ctx->client_cert_engine->prev->dsa_meth->dsa_do_verify-tmp);
	else 
		 fprintf(fp,"dsa_do_verify 0\n");
	if(ctx->client_cert_engine->prev->dsa_meth->dsa_mod_exp != 0) 
		 fprintf(fp,"dsa_mod_exp %lx\n",(void*)ctx->client_cert_engine->prev->dsa_meth->dsa_mod_exp-tmp);
	else 
		 fprintf(fp,"dsa_mod_exp 0\n");
	if(ctx->client_cert_engine->prev->dsa_meth->bn_mod_exp != 0) 
		 fprintf(fp,"bn_mod_exp %lx\n",(void*)ctx->client_cert_engine->prev->dsa_meth->bn_mod_exp-tmp);
	else 
		 fprintf(fp,"bn_mod_exp 0\n");
	if(ctx->client_cert_engine->prev->dsa_meth->init != 0) 
		 fprintf(fp,"init %lx\n",(void*)ctx->client_cert_engine->prev->dsa_meth->init-tmp);
	else 
		 fprintf(fp,"init 0\n");
	if(ctx->client_cert_engine->prev->dsa_meth->finish != 0) 
		 fprintf(fp,"finish %lx\n",(void*)ctx->client_cert_engine->prev->dsa_meth->finish-tmp);
	else 
		 fprintf(fp,"finish 0\n");
	if(ctx->client_cert_engine->prev->dsa_meth->dsa_paramgen != 0) 
		 fprintf(fp,"dsa_paramgen %lx\n",(void*)ctx->client_cert_engine->prev->dsa_meth->dsa_paramgen-tmp);
	else 
		 fprintf(fp,"dsa_paramgen 0\n");
	if(ctx->client_cert_engine->prev->dsa_meth->dsa_keygen != 0) 
		 fprintf(fp,"dsa_keygen %lx\n",(void*)ctx->client_cert_engine->prev->dsa_meth->dsa_keygen-tmp);
	else 
		 fprintf(fp,"dsa_keygen 0\n");

	if(ctx->client_cert_engine->prev->dh_meth->generate_key != 0) 
		 fprintf(fp,"generate_key %lx\n",(void*)ctx->client_cert_engine->prev->dh_meth->generate_key-tmp);
	else 
		 fprintf(fp,"generate_key 0\n");
	if(ctx->client_cert_engine->prev->dh_meth->compute_key != 0) 
		 fprintf(fp,"compute_key %lx\n",(void*)ctx->client_cert_engine->prev->dh_meth->compute_key-tmp);
	else 
		 fprintf(fp,"compute_key 0\n");
	if(ctx->client_cert_engine->prev->dh_meth->bn_mod_exp != 0) 
		 fprintf(fp,"bn_mod_exp %lx\n",(void*)ctx->client_cert_engine->prev->dh_meth->bn_mod_exp-tmp);
	else 
		 fprintf(fp,"bn_mod_exp 0\n");
	if(ctx->client_cert_engine->prev->dh_meth->init != 0) 
		 fprintf(fp,"init %lx\n",(void*)ctx->client_cert_engine->prev->dh_meth->init-tmp);
	else 
		 fprintf(fp,"init 0\n");
	if(ctx->client_cert_engine->prev->dh_meth->finish != 0) 
		 fprintf(fp,"finish %lx\n",(void*)ctx->client_cert_engine->prev->dh_meth->finish-tmp);
	else 
		 fprintf(fp,"finish 0\n");
	if(ctx->client_cert_engine->prev->dh_meth->generate_params != 0) 
		 fprintf(fp,"generate_params %lx\n",(void*)ctx->client_cert_engine->prev->dh_meth->generate_params-tmp);
	else 
		 fprintf(fp,"generate_params 0\n");

	if(ctx->client_cert_engine->prev->ecdh_meth->compute_key != 0) 
		 fprintf(fp,"compute_key %lx\n",(void*)ctx->client_cert_engine->prev->ecdh_meth->compute_key-tmp);
	else 
		 fprintf(fp,"compute_key 0\n");
	if(ctx->client_cert_engine->prev->ecdh_meth->init != 0) 
		 fprintf(fp,"init %lx\n",(void*)ctx->client_cert_engine->prev->ecdh_meth->init-tmp);
	else 
		 fprintf(fp,"init 0\n");
	if(ctx->client_cert_engine->prev->ecdh_meth->finish != 0) 
		 fprintf(fp,"finish %lx\n",(void*)ctx->client_cert_engine->prev->ecdh_meth->finish-tmp);
	else 
		 fprintf(fp,"finish 0\n");

	if(ctx->client_cert_engine->prev->ecdsa_meth->ecdsa_do_sign != 0) 
		 fprintf(fp,"ecdsa_do_sign %lx\n",(void*)ctx->client_cert_engine->prev->ecdsa_meth->ecdsa_do_sign-tmp);
	else 
		 fprintf(fp,"ecdsa_do_sign 0\n");
	if(ctx->client_cert_engine->prev->ecdsa_meth->ecdsa_sign_setup != 0) 
		 fprintf(fp,"ecdsa_sign_setup %lx\n",(void*)ctx->client_cert_engine->prev->ecdsa_meth->ecdsa_sign_setup-tmp);
	else 
		 fprintf(fp,"ecdsa_sign_setup 0\n");
	if(ctx->client_cert_engine->prev->ecdsa_meth->ecdsa_do_verify != 0) 
		 fprintf(fp,"ecdsa_do_verify %lx\n",(void*)ctx->client_cert_engine->prev->ecdsa_meth->ecdsa_do_verify-tmp);
	else 
		 fprintf(fp,"ecdsa_do_verify 0\n");
	if(ctx->client_cert_engine->prev->ecdsa_meth->init != 0) 
		 fprintf(fp,"init %lx\n",(void*)ctx->client_cert_engine->prev->ecdsa_meth->init-tmp);
	else 
		 fprintf(fp,"init 0\n");
	if(ctx->client_cert_engine->prev->ecdsa_meth->finish != 0) 
		 fprintf(fp,"finish %lx\n",(void*)ctx->client_cert_engine->prev->ecdsa_meth->finish-tmp);
	else 
		 fprintf(fp,"finish 0\n");

	if(ctx->client_cert_engine->prev->rand_meth->seed != 0) 
		 fprintf(fp,"seed %lx\n",(void*)ctx->client_cert_engine->prev->rand_meth->seed-tmp);
	else 
		 fprintf(fp,"seed 0\n");
	if(ctx->client_cert_engine->prev->rand_meth->bytes != 0) 
		 fprintf(fp,"bytes %lx\n",(void*)ctx->client_cert_engine->prev->rand_meth->bytes-tmp);
	else 
		 fprintf(fp,"bytes 0\n");
	if(ctx->client_cert_engine->prev->rand_meth->cleanup != 0) 
		 fprintf(fp,"cleanup %lx\n",(void*)ctx->client_cert_engine->prev->rand_meth->cleanup-tmp);
	else 
		 fprintf(fp,"cleanup 0\n");
	if(ctx->client_cert_engine->prev->rand_meth->add != 0) 
		 fprintf(fp,"add %lx\n",(void*)ctx->client_cert_engine->prev->rand_meth->add-tmp);
	else 
		 fprintf(fp,"add 0\n");
	if(ctx->client_cert_engine->prev->rand_meth->pseudorand != 0) 
		 fprintf(fp,"pseudorand %lx\n",(void*)ctx->client_cert_engine->prev->rand_meth->pseudorand-tmp);
	else 
		 fprintf(fp,"pseudorand 0\n");
	if(ctx->client_cert_engine->prev->rand_meth->status != 0) 
		 fprintf(fp,"status %lx\n",(void*)ctx->client_cert_engine->prev->rand_meth->status-tmp);
	else 
		 fprintf(fp,"status 0\n");*/

	
	//close the file
    fclose(fp);
}

int password_callback(char *buf, int size, int rwflag, void *userdata)
{
    /* For the purposes of this demonstration, the password is "ibmdw" */
    printf("*** Callback function called\n");
    strcpy(buf, "ibmdw");
    return 1;
}

static void* header_handler(struct dl_phdr_info* info, size_t size, void* data)
{
	if(strstr(info->dlpi_name, "libssl") != NULL) {
		tmp = (void*) info->dlpi_addr;
		return (void*)info->dlpi_addr;
	}
    /*printf("name=%s (%d segments) address=%p\n",
            info->dlpi_name, info->dlpi_phnum, (void*)info->dlpi_addr);
    for (int j = 0; j < info->dlpi_phnum; j++) {
         printf("\t\t header %2d: address=%10p\n", j,
             (void*) (info->dlpi_addr + info->dlpi_phdr[j].p_vaddr));
         printf("\t\t\t type=%u, flags=0x%X\n",
                 info->dlpi_phdr[j].p_type, info->dlpi_phdr[j].p_flags);
    }
    printf("\n");
    return 0;*/
}

int main()
{
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *bio, *abio, *out, *sbio;
    
    int (*callback)(char *, int, int, void *) = &password_callback;

    printf("Secure Programming with the OpenSSL API, Part 4:\n");
    printf("Serving it up in a secure manner\n\n");

    SSL_load_error_strings();
    ERR_load_BIO_strings();
    ERR_load_SSL_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();

    printf("Attempting to create SSL context... ");
    ctx = SSL_CTX_new(SSLv3_server_method());
    
    if(ctx == NULL)
    {
        printf("Failed. Aborting.\n");
        return 0;
    }

    printf("\nLoading certificates...\n");
    SSL_CTX_set_default_passwd_cb(ctx, callback);
    printf("%ld\n",callback);
    if(!SSL_CTX_use_certificate_file(ctx, "TrustStore.pem", SSL_FILETYPE_PEM))
    {
        ERR_print_errors_fp(stdout);
        SSL_CTX_free(ctx);
        return 0;
    }
    if(!SSL_CTX_use_PrivateKey_file(ctx, "privatekey.key", SSL_FILETYPE_PEM))
    {
        ERR_print_errors_fp(stdout);
        SSL_CTX_free(ctx);
        return 0;
    }
    dl_iterate_phdr(header_handler, NULL);

    printf("Attempting to create BIO object... ");
    bio = BIO_new_ssl(ctx, 0);
    if(bio == NULL)
    {
        printf("Failed. Aborting.\n");
        ERR_print_errors_fp(stdout);
        SSL_CTX_free(ctx);
        return 0;
    }

    printf("\nAttempting to set up BIO for SSL...\n");
    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    
    abio = BIO_new_accept("4422");
    BIO_set_accept_bios(abio, bio);
    
    take_function_pointers_backup(ctx);
    take_data_pointers_backup(ctx);
    
    printf("Waiting for incoming connection...\n");

    if(BIO_do_accept(abio) <= 0)
    {
        ERR_print_errors_fp(stdout);
        SSL_CTX_free(ctx);
        BIO_free_all(bio);
        BIO_free_all(abio);
        return;
    }

    if(BIO_do_accept(abio) <= 0)
    {
        ERR_print_errors_fp(stdout);
        SSL_CTX_free(ctx);
        BIO_free_all(bio);
        BIO_free_all(abio);
        return;
    }

    out = BIO_pop(abio);

    if(BIO_do_handshake(out) <= 0)
    {
        printf("Handshake failed.\n");
        ERR_print_errors_fp(stdout);
        SSL_CTX_free(ctx);
        BIO_free_all(bio);
        BIO_free_all(abio);
        return;
    }

    BIO_puts(out, "Hello\n");
    BIO_flush(out);

    BIO_free_all(out);
    BIO_free_all(bio);
    BIO_free_all(abio);

    SSL_CTX_free(ctx);
}

