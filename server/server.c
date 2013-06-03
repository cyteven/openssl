#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

void take_data_pointers_backup(SSL_CTX *ctx)
{
	//Open File for backup
    FILE *fp;
    fp = fopen("d_backup","w");
    
	fprintf(fp,"%ld\n",ctx->cert_store->objs);
	fprintf(fp,"%ld\n",ctx->method);
	fprintf(fp,"%ld\n",ctx->cipher_list);
	fprintf(fp,"%ld\n",ctx->cipher_list_by_id);
	fprintf(fp,"%ld\n",ctx->cert_store);
	//fprintf(fp,"%ld\n",ctx->name);
	fprintf(fp,"%ld\n",ctx->app_verify_arg);
	fprintf(fp,"%ld\n",ctx->default_passwd_callback_userdata);
	fprintf(fp,"%ld\n",ctx->rsa_md5);
	fprintf(fp,"%ld\n",ctx->md5);
	fprintf(fp,"%ld\n",ctx->sha1);
	fprintf(fp,"%ld\n",ctx->msg_callback_arg);
	fprintf(fp,"%ld\n",ctx->param);
	fprintf(fp,"%ld\n",ctx->tlsext_servername_arg);
	fprintf(fp,"%ld\n",ctx->tlsext_status_arg);
	fprintf(fp,"%ld\n",ctx->tlsext_opaque_prf_input_callback_arg);
	fprintf(fp,"%ld\n",ctx->psk_identity_hint);
	fprintf(fp,"%ld\n",ctx->wbuf_freelist);
	fprintf(fp,"%ld\n",ctx->rbuf_freelist);
	fprintf(fp,"%ld\n",ctx->next_protos_advertised_cb_arg);
	fprintf(fp,"%ld\n",ctx->next_proto_select_cb_arg);
	//fprintf(fp,"%ld\n",ctx->param->name->policies);
	//fprintf(fp,"%ld\n",ctx->param->name->policies->sn);
	//fprintf(fp,"%ld\n",ctx->param->name->policies->ln);
	//fprintf(fp,"%ld\n",ctx->wbuf_freelist->head);
	//fprintf(fp,"%ld\n",ctx->wbuf_freelist->head->next);
	//fprintf(fp,"%ld\n",ctx->rbuf_freelist->head);
	//fprintf(fp,"%ld\n",ctx->rbuf_freelist->head->next);
	
	//Close the file
	fclose(fp);
}

void take_function_pointers_backup(SSL_CTX *ctx) 
{
	//Open File for backup
    FILE *fp;
    fp = fopen("backup","w");
    
	fprintf(fp,"ssl_new %ld\n",ctx->method->ssl_new);
	fprintf(fp,"ssl_clear %ld\n",ctx->method->ssl_clear);
	fprintf(fp,"ssl_free %ld\n",ctx->method->ssl_free);
	fprintf(fp,"ssl_accept %ld\n",ctx->method->ssl_accept);
	fprintf(fp,"ssl_connect %ld\n",ctx->method->ssl_connect);
	fprintf(fp,"ssl_read %ld\n",ctx->method->ssl_read);
	fprintf(fp,"ssl_peek %ld\n",ctx->method->ssl_peek);
	fprintf(fp,"ssl_write %ld\n",ctx->method->ssl_write);
	fprintf(fp,"ssl_shutdown %ld\n",ctx->method->ssl_shutdown);
	fprintf(fp,"ssl_renegotiate %ld\n",ctx->method->ssl_renegotiate);
	fprintf(fp,"ssl_renegotiate_check %ld\n",ctx->method->ssl_renegotiate_check);
	fprintf(fp,"ssl_get_message %ld\n",ctx->method->ssl_get_message);
	fprintf(fp,"ssl_read_bytes %ld\n",ctx->method->ssl_read_bytes);
	fprintf(fp,"ssl_write_bytes %ld\n",ctx->method->ssl_write_bytes);
	fprintf(fp,"ssl_dispatch_alert %ld\n",ctx->method->ssl_dispatch_alert);
	fprintf(fp,"ssl_ctrl %ld\n",ctx->method->ssl_ctrl);
	fprintf(fp,"ssl_ctx_ctrl %ld\n",ctx->method->ssl_ctx_ctrl);
	fprintf(fp,"get_cipher_by_char %ld\n",ctx->method->get_cipher_by_char);
	fprintf(fp,"put_cipher_by_char %ld\n",ctx->method->put_cipher_by_char);
	fprintf(fp,"ssl_pending %ld\n",ctx->method->ssl_pending);
	fprintf(fp,"num_ciphers %ld\n",ctx->method->num_ciphers);
	fprintf(fp,"get_cipher %ld\n",ctx->method->get_cipher);
	fprintf(fp,"get_ssl_method %ld\n",ctx->method->get_ssl_method);
	fprintf(fp,"get_timeout %ld\n",ctx->method->get_timeout);
	fprintf(fp,"ssl_version %ld\n",ctx->method->ssl_version);
	fprintf(fp,"ssl_callback_ctrl %ld\n",ctx->method->ssl_callback_ctrl);
	fprintf(fp,"ssl_ctx_callback_ctrl %ld\n",ctx->method->ssl_ctx_callback_ctrl);
	fprintf(fp,"verify %ld\n",ctx->cert_store->verify);
	fprintf(fp,"verify_cb %ld\n",ctx->cert_store->verify_cb);
	fprintf(fp,"get_issuer %ld\n",ctx->cert_store->get_issuer);
	fprintf(fp,"check_issued %ld\n",ctx->cert_store->check_issued);
	fprintf(fp,"check_revocation %ld\n",ctx->cert_store->check_revocation);
	fprintf(fp,"get_crl %ld\n",ctx->cert_store->get_crl);
	fprintf(fp,"check_crl %ld\n",ctx->cert_store->check_crl);
	fprintf(fp,"cert_crl %ld\n",ctx->cert_store->cert_crl);
	fprintf(fp,"lookup_certs %ld\n",ctx->cert_store->lookup_certs);
	fprintf(fp,"lookup_crls %ld\n",ctx->cert_store->lookup_crls);
	fprintf(fp,"cleanup %ld\n",ctx->cert_store->cleanup);
	fprintf(fp,"new_session_cb %ld\n",ctx->new_session_cb);
	fprintf(fp,"remove_session_cb %ld\n",ctx->remove_session_cb);
	fprintf(fp,"get_session_cb %ld\n",ctx->get_session_cb);
	fprintf(fp,"app_verify_callback %ld\n",ctx->app_verify_callback);
	fprintf(fp,"client_cert_cb %ld\n",ctx->client_cert_cb);
	fprintf(fp,"app_gen_cookie_cb %ld\n",ctx->app_gen_cookie_cb);
	fprintf(fp,"app_verify_cookie_cb %ld\n",ctx->app_verify_cookie_cb);
	fprintf(fp,"init %ld\n",ctx->rsa_md5->init);
	fprintf(fp,"update %ld\n",ctx->rsa_md5->update);
	fprintf(fp,"final %ld\n",ctx->rsa_md5->final);
	fprintf(fp,"copy %ld\n",ctx->rsa_md5->copy);
	fprintf(fp,"cleanup %ld\n",ctx->rsa_md5->cleanup);
	fprintf(fp,"sign %ld\n",ctx->rsa_md5->sign);
	fprintf(fp,"verify %ld\n",ctx->rsa_md5->verify);
	fprintf(fp,"md_ctrl %ld\n",ctx->rsa_md5->md_ctrl);
	fprintf(fp,"init %ld\n",ctx->md5->init);
	fprintf(fp,"update %ld\n",ctx->md5->update);
	fprintf(fp,"final %ld\n",ctx->md5->final);
	fprintf(fp,"copy %ld\n",ctx->md5->copy);
	fprintf(fp,"cleanup %ld\n",ctx->md5->cleanup);
	fprintf(fp,"sign %ld\n",ctx->md5->sign);
	fprintf(fp,"verify %ld\n",ctx->md5->verify);
	fprintf(fp,"md_ctrl %ld\n",ctx->md5->md_ctrl);
	fprintf(fp,"init %ld\n",ctx->sha1->init);
	fprintf(fp,"update %ld\n",ctx->sha1->update);
	fprintf(fp,"final %ld\n",ctx->sha1->final);
	fprintf(fp,"copy %ld\n",ctx->sha1->copy);
	fprintf(fp,"cleanup %ld\n",ctx->sha1->cleanup);
	fprintf(fp,"sign %ld\n",ctx->sha1->sign);
	fprintf(fp,"verify %ld\n",ctx->sha1->verify);
	fprintf(fp,"md_ctrl %ld\n",ctx->sha1->md_ctrl);
	fprintf(fp,"info_callback %ld\n",ctx->info_callback);
	fprintf(fp,"msg_callback %ld\n",ctx->msg_callback);
	fprintf(fp,"default_verify_callback %ld\n",ctx->default_verify_callback);
	fprintf(fp,"tlsext_servername_callback %ld\n",ctx->tlsext_servername_callback);
	fprintf(fp,"tlsext_ticket_key_cb %ld\n",ctx->tlsext_ticket_key_cb);
	fprintf(fp,"tlsext_status_cb %ld\n",ctx->tlsext_status_cb);
	fprintf(fp,"tlsext_opaque_prf_input_callback %ld\n",ctx->tlsext_opaque_prf_input_callback);
	fprintf(fp,"psk_client_callback %ld\n",ctx->psk_client_callback);
	fprintf(fp,"psk_server_callback %ld\n",ctx->psk_server_callback);
	fprintf(fp,"TLS_ext_srp_username_callback %ld\n",ctx->srp_ctx.TLS_ext_srp_username_callback);
	fprintf(fp,"SRP_verify_param_callback %ld\n",ctx->srp_ctx.SRP_verify_param_callback);
	fprintf(fp,"SRP_give_srp_client_pwd_callback %ld\n",ctx->srp_ctx.SRP_give_srp_client_pwd_callback);
	fprintf(fp,"next_protos_advertised_cb %ld\n",ctx->next_protos_advertised_cb);
	fprintf(fp,"next_proto_select_cb %ld\n",ctx->next_proto_select_cb);
	/*fprintf(fp,"%ld",ctx->client_cert_engine->name);
	fprintf(fp,"rsa_pub_dec %ld\n",ctx->client_cert_engine->rsa_meth->rsa_pub_dec);
	fprintf(fp,"rsa_priv_enc %ld\n",ctx->client_cert_engine->rsa_meth->rsa_priv_enc);
	fprintf(fp,"rsa_priv_dec %ld\n",ctx->client_cert_engine->rsa_meth->rsa_priv_dec);
	fprintf(fp,"rsa_mod_exp %ld\n",ctx->client_cert_engine->rsa_meth->rsa_mod_exp);
	fprintf(fp,"bn_mod_exp %ld\n",ctx->client_cert_engine->rsa_meth->bn_mod_exp);
	fprintf(fp,"init %ld\n",ctx->client_cert_engine->rsa_meth->init);
	fprintf(fp,"finish %ld\n",ctx->client_cert_engine->rsa_meth->finish);
	fprintf(fp,"rsa_sign %ld\n",ctx->client_cert_engine->rsa_meth->rsa_sign);
	fprintf(fp,"rsa_verify %ld\n",ctx->client_cert_engine->rsa_meth->rsa_verify);
	fprintf(fp,"rsa_keygen %ld\n",ctx->client_cert_engine->rsa_meth->rsa_keygen);

	fprintf(fp,"dsa_do_sign %ld\n",ctx->client_cert_engine->dsa_meth->dsa_do_sign);
	fprintf(fp,"dsa_sign_setup %ld\n",ctx->client_cert_engine->dsa_meth->dsa_sign_setup);
	fprintf(fp,"dsa_do_verify %ld\n",ctx->client_cert_engine->dsa_meth->dsa_do_verify);
	fprintf(fp,"dsa_mod_exp %ld\n",ctx->client_cert_engine->dsa_meth->dsa_mod_exp);
	fprintf(fp,"bn_mod_exp %ld\n",ctx->client_cert_engine->dsa_meth->bn_mod_exp);
	fprintf(fp,"init %ld\n",ctx->client_cert_engine->dsa_meth->init);
	fprintf(fp,"finish %ld\n",ctx->client_cert_engine->dsa_meth->finish);
	fprintf(fp,"dsa_paramgen %ld\n",ctx->client_cert_engine->dsa_meth->dsa_paramgen);
	fprintf(fp,"dsa_keygen %ld\n",ctx->client_cert_engine->dsa_meth->dsa_keygen);

	fprintf(fp,"generate_key %ld\n",ctx->client_cert_engine->dh_meth->generate_key);
	fprintf(fp,"compute_key %ld\n",ctx->client_cert_engine->dh_meth->compute_key);
	fprintf(fp,"bn_mod_exp %ld\n",ctx->client_cert_engine->dh_meth->bn_mod_exp);
	fprintf(fp,"init %ld\n",ctx->client_cert_engine->dh_meth->init);
	fprintf(fp,"finish %ld\n",ctx->client_cert_engine->dh_meth->finish);
	fprintf(fp,"generate_params %ld\n",ctx->client_cert_engine->dh_meth->generate_params);

	fprintf(fp,"compute_key %ld\n",ctx->client_cert_engine->ecdh_meth->compute_key);
	fprintf(fp,"init %ld\n",ctx->client_cert_engine->ecdh_meth->init);
	fprintf(fp,"finish %ld\n",ctx->client_cert_engine->ecdh_meth->finish);

	fprintf(fp,"ecdsa_do_sign %ld\n",ctx->client_cert_engine->ecdsa_meth->ecdsa_do_sign);
	fprintf(fp,"ecdsa_sign_setup %ld\n",ctx->client_cert_engine->ecdsa_meth->ecdsa_sign_setup);
	fprintf(fp,"ecdsa_do_verify %ld\n",ctx->client_cert_engine->ecdsa_meth->ecdsa_do_verify);
	fprintf(fp,"init %ld\n",ctx->client_cert_engine->ecdsa_meth->init);
	fprintf(fp,"finish %ld\n",ctx->client_cert_engine->ecdsa_meth->finish);

	fprintf(fp,"seed %ld\n",ctx->client_cert_engine->rand_meth->seed);
	fprintf(fp,"bytes %ld\n",ctx->client_cert_engine->rand_meth->bytes);
	fprintf(fp,"cleanup %ld\n",ctx->client_cert_engine->rand_meth->cleanup);
	fprintf(fp,"add %ld\n",ctx->client_cert_engine->rand_meth->add);
	fprintf(fp,"pseudorand %ld\n",ctx->client_cert_engine->rand_meth->pseudorand);
	fprintf(fp,"status %ld\n",ctx->client_cert_engine->rand_meth->status);


	fprintf(fp,"rsa_pub_enc %ld\n",ctx->client_cert_engine->prev->rsa_meth->rsa_pub_enc);
	fprintf(fp,"rsa_pub_dec %ld\n",ctx->client_cert_engine->prev->rsa_meth->rsa_pub_dec);
	fprintf(fp,"rsa_priv_enc %ld\n",ctx->client_cert_engine->prev->rsa_meth->rsa_priv_enc);
	fprintf(fp,"rsa_priv_dec %ld\n",ctx->client_cert_engine->prev->rsa_meth->rsa_priv_dec);
	fprintf(fp,"rsa_mod_exp %ld\n",ctx->client_cert_engine->prev->rsa_meth->rsa_mod_exp);
	fprintf(fp,"bn_mod_exp %ld\n",ctx->client_cert_engine->prev->rsa_meth->bn_mod_exp);
	fprintf(fp,"init %ld\n",ctx->client_cert_engine->prev->rsa_meth->init);
	fprintf(fp,"finish %ld\n",ctx->client_cert_engine->prev->rsa_meth->finish);
	fprintf(fp,"rsa_sign %ld\n",ctx->client_cert_engine->prev->rsa_meth->rsa_sign);
	fprintf(fp,"rsa_verify %ld\n",ctx->client_cert_engine->prev->rsa_meth->rsa_verify);
	fprintf(fp,"rsa_keygen %ld\n",ctx->client_cert_engine->prev->rsa_meth->rsa_keygen);

	fprintf(fp,"dsa_do_sign %ld\n",ctx->client_cert_engine->prev->dsa_meth->dsa_do_sign);
	fprintf(fp,"dsa_sign_setup %ld\n",ctx->client_cert_engine->prev->dsa_meth->dsa_sign_setup);
	fprintf(fp,"dsa_do_verify %ld\n",ctx->client_cert_engine->prev->dsa_meth->dsa_do_verify);
	fprintf(fp,"dsa_mod_exp %ld\n",ctx->client_cert_engine->prev->dsa_meth->dsa_mod_exp);
	fprintf(fp,"bn_mod_exp %ld\n",ctx->client_cert_engine->prev->dsa_meth->bn_mod_exp);
	fprintf(fp,"init %ld\n",ctx->client_cert_engine->prev->dsa_meth->init);
	fprintf(fp,"finish %ld\n",ctx->client_cert_engine->prev->dsa_meth->finish);
	fprintf(fp,"dsa_paramgen %ld\n",ctx->client_cert_engine->prev->dsa_meth->dsa_paramgen);
	fprintf(fp,"dsa_keygen %ld\n",ctx->client_cert_engine->prev->dsa_meth->dsa_keygen);

	fprintf(fp,"generate_key %ld\n",ctx->client_cert_engine->prev->dh_meth->generate_key);
	fprintf(fp,"compute_key %ld\n",ctx->client_cert_engine->prev->dh_meth->compute_key);
	fprintf(fp,"bn_mod_exp %ld\n",ctx->client_cert_engine->prev->dh_meth->bn_mod_exp);
	fprintf(fp,"init %ld\n",ctx->client_cert_engine->prev->dh_meth->init);
	fprintf(fp,"finish %ld\n",ctx->client_cert_engine->prev->dh_meth->finish);
	fprintf(fp,"generate_params %ld\n",ctx->client_cert_engine->prev->dh_meth->generate_params);

	fprintf(fp,"compute_key %ld\n",ctx->client_cert_engine->prev->ecdh_meth->compute_key);
	fprintf(fp,"init %ld\n",ctx->client_cert_engine->prev->ecdh_meth->init);
	fprintf(fp,"finish %ld\n",ctx->client_cert_engine->prev->ecdh_meth->finish);

	fprintf(fp,"ecdsa_do_sign %ld\n",ctx->client_cert_engine->prev->ecdsa_meth->ecdsa_do_sign);
	fprintf(fp,"ecdsa_sign_setup %ld\n",ctx->client_cert_engine->prev->ecdsa_meth->ecdsa_sign_setup);
	fprintf(fp,"ecdsa_do_verify %ld\n",ctx->client_cert_engine->prev->ecdsa_meth->ecdsa_do_verify);
	fprintf(fp,"init %ld\n",ctx->client_cert_engine->prev->ecdsa_meth->init);
	fprintf(fp,"finish %ld\n",ctx->client_cert_engine->prev->ecdsa_meth->finish);

	fprintf(fp,"seed %ld\n",ctx->client_cert_engine->prev->rand_meth->seed);
	fprintf(fp,"bytes %ld\n",ctx->client_cert_engine->prev->rand_meth->bytes);
	fprintf(fp,"cleanup %ld\n",ctx->client_cert_engine->prev->rand_meth->cleanup);
	fprintf(fp,"add %ld\n",ctx->client_cert_engine->prev->rand_meth->add);
	fprintf(fp,"pseudorand %ld\n",ctx->client_cert_engine->prev->rand_meth->pseudorand);
	fprintf(fp,"status %ld\n",ctx->client_cert_engine->prev->rand_meth->status);


	fprintf(fp,"rsa_pub_enc %ld\n",ctx->client_cert_engine->prev->rsa_meth->rsa_pub_enc);
	fprintf(fp,"rsa_pub_dec %ld\n",ctx->client_cert_engine->prev->rsa_meth->rsa_pub_dec);
	fprintf(fp,"rsa_priv_enc %ld\n",ctx->client_cert_engine->prev->rsa_meth->rsa_priv_enc);
	fprintf(fp,"rsa_priv_dec %ld\n",ctx->client_cert_engine->prev->rsa_meth->rsa_priv_dec);
	fprintf(fp,"rsa_mod_exp %ld\n",ctx->client_cert_engine->prev->rsa_meth->rsa_mod_exp);
	fprintf(fp,"bn_mod_exp %ld\n",ctx->client_cert_engine->prev->rsa_meth->bn_mod_exp);
	fprintf(fp,"init %ld\n",ctx->client_cert_engine->prev->rsa_meth->init);
	fprintf(fp,"finish %ld\n",ctx->client_cert_engine->prev->rsa_meth->finish);
	fprintf(fp,"rsa_sign %ld\n",ctx->client_cert_engine->prev->rsa_meth->rsa_sign);
	fprintf(fp,"rsa_verify %ld\n",ctx->client_cert_engine->prev->rsa_meth->rsa_verify);
	fprintf(fp,"rsa_keygen %ld\n",ctx->client_cert_engine->prev->rsa_meth->rsa_keygen);

	fprintf(fp,"dsa_do_sign %ld\n",ctx->client_cert_engine->prev->dsa_meth->dsa_do_sign);
	fprintf(fp,"dsa_sign_setup %ld\n",ctx->client_cert_engine->prev->dsa_meth->dsa_sign_setup);
	fprintf(fp,"dsa_do_verify %ld\n",ctx->client_cert_engine->prev->dsa_meth->dsa_do_verify);
	fprintf(fp,"dsa_mod_exp %ld\n",ctx->client_cert_engine->prev->dsa_meth->dsa_mod_exp);
	fprintf(fp,"bn_mod_exp %ld\n",ctx->client_cert_engine->prev->dsa_meth->bn_mod_exp);
	fprintf(fp,"init %ld\n",ctx->client_cert_engine->prev->dsa_meth->init);
	fprintf(fp,"finish %ld\n",ctx->client_cert_engine->prev->dsa_meth->finish);
	fprintf(fp,"dsa_paramgen %ld\n",ctx->client_cert_engine->prev->dsa_meth->dsa_paramgen);
	fprintf(fp,"dsa_keygen %ld\n",ctx->client_cert_engine->prev->dsa_meth->dsa_keygen);

	fprintf(fp,"generate_key %ld\n",ctx->client_cert_engine->prev->dh_meth->generate_key);
	fprintf(fp,"compute_key %ld\n",ctx->client_cert_engine->prev->dh_meth->compute_key);
	fprintf(fp,"bn_mod_exp %ld\n",ctx->client_cert_engine->prev->dh_meth->bn_mod_exp);
	fprintf(fp,"init %ld\n",ctx->client_cert_engine->prev->dh_meth->init);
	fprintf(fp,"finish %ld\n",ctx->client_cert_engine->prev->dh_meth->finish);
	fprintf(fp,"generate_params %ld\n",ctx->client_cert_engine->prev->dh_meth->generate_params);

	fprintf(fp,"compute_key %ld\n",ctx->client_cert_engine->prev->ecdh_meth->compute_key);
	fprintf(fp,"init %ld\n",ctx->client_cert_engine->prev->ecdh_meth->init);
	fprintf(fp,"finish %ld\n",ctx->client_cert_engine->prev->ecdh_meth->finish);

	fprintf(fp,"ecdsa_do_sign %ld\n",ctx->client_cert_engine->prev->ecdsa_meth->ecdsa_do_sign);
	fprintf(fp,"ecdsa_sign_setup %ld\n",ctx->client_cert_engine->prev->ecdsa_meth->ecdsa_sign_setup);
	fprintf(fp,"ecdsa_do_verify %ld\n",ctx->client_cert_engine->prev->ecdsa_meth->ecdsa_do_verify);
	fprintf(fp,"init %ld\n",ctx->client_cert_engine->prev->ecdsa_meth->init);
	fprintf(fp,"finish %ld\n",ctx->client_cert_engine->prev->ecdsa_meth->finish);

	fprintf(fp,"seed %ld\n",ctx->client_cert_engine->prev->rand_meth->seed);
	fprintf(fp,"bytes %ld\n",ctx->client_cert_engine->prev->rand_meth->bytes);
	fprintf(fp,"cleanup %ld\n",ctx->client_cert_engine->prev->rand_meth->cleanup);
	fprintf(fp,"add %ld\n",ctx->client_cert_engine->prev->rand_meth->add);
	fprintf(fp,"pseudorand %ld\n",ctx->client_cert_engine->prev->rand_meth->pseudorand);
	fprintf(fp,"status %ld\n",ctx->client_cert_engine->prev->rand_meth->status);*/
	
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

